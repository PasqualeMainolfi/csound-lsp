use std::time::Duration;
use std::path::Path;
use std::io;
use tower_lsp::lsp_types::SemanticTokenType;
use serde::Deserialize;
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

pub const OMACROS: [&'static str; 13] = [
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
    "M_SQRT1_2"
];

pub const OPEN_BLOCKS: [&'static str; 14] = [
    "instrument_definition",
    "udo_definition_legacy",
    "udo_definition_modern",
    "internal_code_block",
    "if_statement",
    "else_block",
    "elseif_block",
    "switch_statement",
    "case_block",
    "default_block",
    "while_loop",
    "until_loop",
    "for_loop" ,
    "score_nestable_loop"
];

pub const CLOSE_BLOCKS: [&'static str; 16] = [
    "kw_endin",
    "kw_endop",
    "kw_endif",
    "kw_fi",
    "kw_od",
    "kw_switch_end",
    "kw_else",
    "kw_elseif",
    "kw_case_key",
    "kw_default_key",
    "endsw",
    "else_block",
    "elseif_block",
    "case_header",
    "default_header",
    "}"
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
