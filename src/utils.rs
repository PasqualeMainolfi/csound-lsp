#![allow(unused)]
use crate::parser;
use std::path::{Path, PathBuf};
use std::io;
use reqwest::Client;
use tower_lsp::lsp_types::{
    CompletionItem,
    CompletionItemKind,
    Diagnostic,
    DiagnosticSeverity,
    DiagnosticTag,
    Hover,
    HoverContents,
    MarkupContent,
    MarkupKind,
    Position,
    SemanticTokenType,
    Documentation
};
use serde::Deserialize;
use tree_sitter::Node;
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
    let response = reqwest::get(url).await?;

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

pub fn find_char_byte(line: &str, target_char: usize) -> usize {
    let mut current_char_utf16 = 0 as usize;
    let mut current_char_utf8 = 0 as usize;
    for char in line.chars() {
        let char_utf16 = char.len_utf16();
        if current_char_utf16 + char_utf16 >= target_char {
            break;
        }
        current_char_utf16 += char_utf16;
        current_char_utf8 += char.len_utf8();
    }
    current_char_utf8
}

pub fn position_to_start_byte(pos: &Position, text: &String) -> usize {
    let target_line = pos.line as usize;
    let target_char = pos.character as usize;
    let mut offset = 0;
    for (i, line) in text.lines().enumerate() {
        if i == target_line as usize {
            let current_char = find_char_byte(line, target_char);
            offset += current_char;
            break;
        } else {
            offset += line.len() + 1;
        }
    }
    offset
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

pub fn completion_helper(label: String, kind: CompletionItemKind, detail: String, text: String, doc: String) -> CompletionItem {
    CompletionItem {
        label: label,
        kind: Some(kind),
        detail: Some(detail),
        insert_text: Some(text),
        documentation: Some(Documentation::String(doc)),
        ..Default::default()
    }
}
