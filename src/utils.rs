use crate::parser;
use std::time::Duration;
use std::path::{Path, PathBuf};
use std::io;
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

pub async fn get_release_tag_from_github(github_api_latest: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("csound-lsp")
        .build()?;

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

pub async fn copy_dir_recursively(src: &Path, dest: &Path) -> std::io::Result<()> {
    if !dest.exists() {
        tokio::fs::create_dir_all(&dest).await?;
    }

    let mut entries = tokio::fs::read_dir(&src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let epath = entry.path();
        let dest_path = dest.join(&entry.file_name());
        if epath.is_dir() {
            Box::pin(copy_dir_recursively(&epath, &dest_path)).await?;
        } else {
            tokio::fs::copy(&epath, &dest_path).await?;
        }
    }

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

pub fn undefined_message_from_kind(nkind: &str) -> String {
    match nkind {
        "label_statement" => return "Undefined label".to_string(),
        "macro_usage"     => return "Undefined macro".to_string(),
        _                 => return "Undefined variable".to_string(),
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
