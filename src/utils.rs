#![allow(unused)]
use crate::parser;
use std::path::{Path, PathBuf};
use std::io;
use reqwest::Client;
use ropey::Rope;
use tower_lsp::lsp_types::{
    Diagnostic,
    DiagnosticSeverity,
    DiagnosticTag,
    Hover,
    HoverContents,
    MarkupContent,
    MarkupKind,
    Position,
    Range,
    SemanticTokenType
};
use serde::Deserialize;
use tree_sitter::{ Node, Point };
use zip::ZipArchive;


pub const SEMANTIC_TOKENS: &[SemanticTokenType] = &[
    SemanticTokenType::DECORATOR,
    SemanticTokenType::PARAMETER,
    SemanticTokenType::MACRO,
    SemanticTokenType::TYPE,
    SemanticTokenType::COMMENT,
    SemanticTokenType::KEYWORD,
    SemanticTokenType::PROPERTY,
    SemanticTokenType::NAMESPACE,
    SemanticTokenType::VARIABLE,
    SemanticTokenType::STRING,
    SemanticTokenType::NUMBER,
    SemanticTokenType::FUNCTION,
    SemanticTokenType::OPERATOR
];

pub const OMACROS: [&'static str; 15] = [
    "M_E",
    "MLOG2E",
    "M_LOG10E",
    "M_LN2",
    "M_LN10",
    "M_PI",
    "M_PI_2",
    "M_PI_4",
    "M_1_PI",
    "M_2_PI",
    "M_2_SQRTPI",
    "M_SQRT2",
    "M_MAX_VALUE",
    "M_MIN_VALUE",
    "M_INF"
];

pub const OPEN_BLOCKS: [&'static str; 10] = [
    "instrument_definition",
    "udo_definition_legacy",
    "udo_definition_modern",
    "internal_code_block",
    "if_statement",
    "switch_statement",
    "while_loop",
    "until_loop",
    "for_loop" ,
    "score_nestable_loop"
];

pub const CLOSE_BLOCKS: [&'static str; 10] = [
    "endin",
    "endop",
    "kw_fi",
    "kw_endif",
    "kw_od",
    "kw_switch_end",
    "kw_case",
    "kw_default",
    "endsw",
    "}"
];

pub const OPENER: [&'static str; 7] = [
    "kw_then",
    "kw_ithen",
    "kw_kthen",
    "instr",
    "opcode",
    "kw_do",
    "{"
];

#[derive(Deserialize)]
pub struct ReleaseTag {
    tag_name: String
}

#[derive(Debug, Deserialize)]
pub struct GitHubEntry {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub download_url: Option<String>
}

pub enum PVersionAge {
    Oldest,
    Newest,
    Same
}

#[derive(Debug)]
pub struct PVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32
}

impl PVersion {
    pub fn new(string_version: &str) -> Self {
        let mut parts = string_version.trim_start_matches('v').split('.');
        let major = Self::parse_component(parts.next());
        let minor = Self::parse_component(parts.next());
        let patch = Self::parse_component(parts.next());

        Self { major, minor, patch }
    }

    fn parse_component(component: Option<&str>) -> u32 {
        component
            .map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    }

    pub fn compare(&self, version: &PVersion) -> PVersionAge {
        if self.major != version.major {
            return if self.major < version.major {
                PVersionAge::Oldest
            } else {
                PVersionAge::Newest
            };
        }

        if self.minor != version.minor {
            return if self.minor < version.minor {
                PVersionAge::Oldest
            } else {
                PVersionAge::Newest
            };
        }

        if self.patch != version.patch {
            return if self.patch < version.patch {
                PVersionAge::Oldest
            } else {
                PVersionAge::Newest
            };
        }

        PVersionAge::Same
    }
}


pub fn parse_plugins_git_url(url: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let trimmed = url.trim_end_matches(".git").trim_end_matches('/');
    let splitted: Vec<&str> = trimmed.split('/').collect();
    let owner = splitted.get(splitted.len() - 2).ok_or("missing owner in git url")?.to_string();
    let repos = splitted.last().ok_or("missing repos in git url")?.to_string();
    Ok((owner, repos))
}

pub async fn get_release_tag_from_github(client: &Client, github_api_latest: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let release: ReleaseTag = client
        .get(github_api_latest)
        .send()
        .await?
        .json()
        .await?;

    Ok(release.tag_name)
}

pub async fn download_from_github(url: &str, temp_path: &Path, local_file: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("csound-lsp")
        .build()?;
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(format!("Download from {} failed: {}", url, response.status()).into());
    }

    let zip_file = temp_path.join(local_file);
    let mut file = tokio::fs::File::create(zip_file).await?;
    let bytes = response.bytes().await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;

    Ok(())
}

pub fn unzip_file(zip_archive_path: &Path, dir_name: &Path) -> io::Result<()> {
    let file = std::fs::File::open(zip_archive_path)?;
    let mut archive = ZipArchive::new(file)?;

    archive.extract(dir_name)?;
    std::fs::remove_file(&zip_archive_path)?;

    Ok(())
}

pub fn check_valid_resource_dir(dir: &Path, label: &str) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(ent) => ent,
        Err(e) => return Err(format!("{}: no valid resource dir founded {}", label, e).into())
    };

    for entry in entries {
        let entry = match entry {
            Ok(ent) => ent,
            Err(_) => continue
        };

        let epath = entry.path();
        let is_valid_dir = epath.is_dir() && epath
            .file_name()
            .and_then(|n| n.to_str())
            .map(|name| name.to_string().contains(label))
            .unwrap_or(false);

        if is_valid_dir {
            return Ok(epath.clone());
        }
    }

    Err(format!("{}: no valid resource dir founded", label).into())
}

// LSP positions count UTF-16 code units, tree-sitter points count bytes.

fn line_len_chars(line: ropey::RopeSlice) -> usize {
    let mut len = line.len_chars();
    while len > 0 && matches!(line.char(len - 1), '\n' | '\r') {
        len -= 1;
    }
    len
}

// char index of an LSP position, clamped to the line and to the document
pub fn lsp_position_to_char(text: &Rope, pos: &Position) -> usize {
    let row = pos.line as usize;
    if row >= text.len_lines() {
        return text.len_chars();
    }
    let line = text.line(row);
    let max_units = line.char_to_utf16_cu(line_len_chars(line));
    text.line_to_char(row) + line.utf16_cu_to_char((pos.character as usize).min(max_units))
}

pub fn char_to_point(text: &Rope, char_idx: usize) -> Point {
    let row = text.char_to_line(char_idx);
    Point { row, column: text.char_to_byte(char_idx) - text.line_to_byte(row) }
}

pub fn lsp_position_to_point(text: &Rope, pos: &Position) -> Point {
    char_to_point(text, lsp_position_to_char(text, pos))
}

pub fn point_to_lsp_position(text: &Rope, row: usize, column: usize) -> Position {
    if row >= text.len_lines() {
        return Position::new(row as u32, column as u32);
    }
    let line = text.line(row);
    let char_idx = line.byte_to_char(column.min(line.len_bytes()));
    Position::new(row as u32, line.char_to_utf16_cu(char_idx) as u32)
}

// converts a range built from tree-sitter points (byte columns) to UTF-16 columns
pub fn range_to_utf16(text: &Rope, range: Range) -> Range {
    Range {
        start: point_to_lsp_position(text, range.start.line as usize, range.start.character as usize),
        end: point_to_lsp_position(text, range.end.line as usize, range.end.character as usize)
    }
}

pub fn diagnostic_helper(node: &Node, severity: DiagnosticSeverity, message: String, tags: Option<Vec<DiagnosticTag>>) -> Diagnostic {
    Diagnostic {
        range: parser::get_node_range(node, None),
        severity: Some(severity),
        source: Some("csound-lsp".into()),
        message: message,
        tags: tags,
        ..Default::default()
    }
}

pub fn undefined_message_from_kind(pkind: &str) -> String {
    match pkind {
        "goto_statement" |
        "rigoto_statement" => return "Undefined label".to_string(),
        "macro_usage"      => return "Undefined macro".to_string(),
        _                  => return "Undefined variable".to_string(),
    }
}

pub fn unused_message_from_kind(nkind: &str) -> String {
    match nkind {
        "label_statement" => return "Unused label".to_string(),
        "macro_usage"     => return "Unused macro".to_string(),
        _                 => return "Unused variable".to_string(),
    }
}

pub fn hover_helper(doc: String) -> Hover {
    Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: doc,
        }),
        range: None,
    }
}
