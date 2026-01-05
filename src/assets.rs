use std::{
    io,
    path::{ Path, PathBuf },
    time::Duration
};
use regex::{ Regex, Captures };
use std::collections::HashMap;
use reqwest;
use zip::ZipArchive;
use serde::Deserialize;

pub const TEMP_CSOUND_MANUAL_DIR: &str = "temp_csound_manual";
pub const GITHUB_LATEST_API: &str = "https://api.github.com/repos/PasqualeMainolfi/csound_manual/releases/latest";
pub const GITHUB_DOWNLOAD_BASE: &str = "https://github.com/PasqualeMainolfi/csound_manual/releases/download";
pub const ASSET_NAME: &str = "csound_manual-html.zip";
pub const OPCODES_MD_DIR: &str = "csound_resources/opcodes";
pub const EXAMPLES_DIR: &str = "csound_resources/examples";
pub const OPCODES_QUERY: &str = "csound_resources/csound.json";
pub const FLAGS_QUERY: &str = "csound_resources/flags.json";
pub const MACROS_QUERY: &str = "csound_resources/macros.json";

#[derive(Deserialize)]
pub struct ManualTag {
    tag_name: String
}

async fn get_release_tag() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("csound-lsp")
        .build()?;

    let release: ManualTag = client
        .get(GITHUB_LATEST_API)
        .send()
        .await?
        .json()
        .await?;

    Ok(release.tag_name)
}

async fn download_manual(url: &str, temp_path: &Path, release_tag: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = reqwest::get(url).await?;

    if !response.status().is_success() {
        return Err(format!("Download from {} failed: {}", url, response.status()).into());
    }

    // local path not ci
    let zip_manual_file = temp_path.join(format!("csound_manual-html_{}.zip", release_tag));
    let mut file = tokio::fs::File::create(zip_manual_file).await?;
    let bytes = response.bytes().await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await?;

    Ok(())
}

fn unzip_file(zip_archive_path: &Path, maual_dir_name: &Path) -> io::Result<()> {
    let file = std::fs::File::open(zip_archive_path)?;
    let mut archive = ZipArchive::new(file)?;

    archive.extract(maual_dir_name)?;
    std::fs::remove_file(&zip_archive_path)?;

    Ok(())
}

fn load_opcodes(opcodes_folder: &Path, examples_folder: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let iter_dir = std::fs::read_dir(&opcodes_folder).ok();
    if let Some(d) = iter_dir {
        for entry in d {
            let entry = entry.ok();
            if let Some(f) = entry {
                let file = f.path();
                if file.extension().and_then(|e| e.to_str()) == Some("md") {
                    let name = file
                        .file_stem().and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_string();

                    let file_to_string = std::fs::read_to_string(&file).ok();

                    if let Some(content_file) = file_to_string {
                        let content = expand_includes(&content_file, &examples_folder);

                        let re_code = Regex::new(r"```[ \t]*csound[^\n]*").unwrap();
                        let content = re_code.replace_all(&content, "\n```csound\n").to_string();

                        let re_code = Regex::new(r"[ \t]*(```\n)").unwrap();
                        let content = re_code.replace_all(&content, "\n```\n").to_string();

                        let re = Regex::new(r"<br\s*/?>").unwrap();
                        let content = re.replace_all(&content, "\n\n").to_string();

                        map.insert(name, content);
                    }
                }
            }
        }
    }
    map
}

fn expand_includes(content: &str, examples_folder: &Path) -> String {
    let rex = Regex::new(r#"--8<--\s+"([^"]+)""#).unwrap();
    rex.replace_all(content, |cap: &Captures| {
        let cap_str = &cap[1].to_string();
        let entire_path = Path::new(cap_str);
        let path = entire_path.file_name().and_then(|f| f.to_str()).unwrap();
        let internal_path = examples_folder.join(path);
        match std::fs::read_to_string(&internal_path) {
            Ok(f) => f,
            Err(_) => format!("<!-- undefined includes {} -->", path)
        }
    }).to_string()
}

pub async fn load_manual_resources(
    temp_folder_name: &str, json_opcodes: &mut HashMap<String, String>, temp_manual_path: &mut PathBuf
) -> Result<(), Box<dyn std::error::Error + Sync + Send>>{
    let mut temp_dir = std::env::temp_dir();
    temp_dir.push(temp_folder_name);

    let check_release_tag = get_release_tag().await;
    let release_tag = match check_release_tag {
        Ok(tag) => tag,
        Err(_) => "v-error".to_string() // verify prec version
    };

    let dir_name = format!("csound_manual-html_{}", &release_tag);
    let manual_dir_path = temp_dir.join(&dir_name);

    if !manual_dir_path.exists() && release_tag != "v-error" {
        if temp_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        }

        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let download_url = format!("{}/{}/{}", GITHUB_DOWNLOAD_BASE, release_tag, ASSET_NAME);
        download_manual(&download_url, &temp_dir, &release_tag).await?;

        let zip_name = format!("csound_manual-html_{}.zip", release_tag);
        let zip_archive_path = temp_dir.join(zip_name);
        let target_dir = manual_dir_path.clone();

        tokio::task::spawn_blocking(move || {
            if !target_dir.exists() { std::fs::create_dir_all(&target_dir)?; }
            unzip_file(&zip_archive_path, &target_dir)
        }).await??;

    }

    let op_path = manual_dir_path.join(&OPCODES_MD_DIR);
    let ex_path = manual_dir_path.join(&EXAMPLES_DIR);

    if op_path.exists() {
        let opcodes = load_opcodes(&op_path, &ex_path);

        *json_opcodes = opcodes;
        *temp_manual_path = manual_dir_path.clone();
    }

    Ok(())
}


#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum BodyOpCompletion {
    SingleLine(String),
    MultipleLine(Vec<String>)
}

#[derive(Deserialize, Debug)]
pub struct OpcodesData {
    pub prefix: String,
    pub body: BodyOpCompletion,
    pub description: String
}

impl OpcodesData {
    pub fn get_string_from_body(&self) -> String {
        match &self.body {
            BodyOpCompletion::SingleLine(s) => s.clone(),
            BodyOpCompletion::MultipleLine(arr) => arr.join("\n")
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct OMacro {
    pub value: String,
    pub equivalent_to: String
}

#[derive(Debug, Default)]
pub struct CsoundJsonData {
    pub opcodes_data: Option<HashMap<String, OpcodesData>>,
    pub omacros_data: Option<HashMap<String, OMacro>>,
    pub oflag_data: Option<HashMap<String, OpcodesData>>
}

pub async fn read_csound_json_data(cj: &mut CsoundJsonData, base_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let json_opcodes = base_dir.join(OPCODES_QUERY);
    if let Ok(jop) = tokio::fs::read_to_string(&json_opcodes).await {
        cj.opcodes_data = match serde_json::from_str::<HashMap<String, OpcodesData>>(&jop) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("ERROR: Could not parse opcode JSON: {}", e);
                None
            }
        }
    }


    let json_macros = base_dir.join(MACROS_QUERY);
    if let Ok(jma) = tokio::fs::read_to_string(&json_macros).await {
        cj.omacros_data = match serde_json::from_str::<HashMap<String, OMacro>>(&jma) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("ERROR: Could not parse omacro JSON: {}", e);
                None
            }
        }
    }

    let json_flags = base_dir.join(FLAGS_QUERY);
    if let Ok(jfl) = tokio::fs::read_to_string(&json_flags).await {
        cj.oflag_data = match serde_json::from_str::<HashMap<String, OpcodesData>>(&jfl) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("ERROR: Could not parse flag JSON: {}", e);
                None
            }
        }
    }

    Ok(())
}
