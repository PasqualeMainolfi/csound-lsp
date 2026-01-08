use crate::utils;

use std::path::{ Path, PathBuf };
use regex::{ Regex, Captures };
use std::collections::HashMap;
use serde::Deserialize;


pub const TEMP_CSOUND_MANUAL_DIR: &str = "temp_csound_manual";
pub const GITHUB_LATEST_API_MANUAL: &str = "https://api.github.com/repos/PasqualeMainolfi/csound_manual/releases/latest";
pub const GITHUB_DOWNLOAD_BASE_MANUAL: &str = "https://github.com/PasqualeMainolfi/csound_manual/releases/download";
pub const ASSET_NAME: &str = "csound_manual-html.zip";
pub const OPCODES_MD_DIR: &str = "csound_resources/opcodes";
pub const EXAMPLES_DIR: &str = "csound_resources/examples";
pub const OPCODES_QUERY: &str = "csound_resources/csound.json";
pub const FLAGS_QUERY: &str = "csound_resources/flags.json";
pub const MACROS_QUERY: &str = "csound_resources/macros.json";

fn load_opcodes(opcodes_folder: &Path, examples_folder: &Path) -> std::io::Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    let re_csound = Regex::new(r"```[ \t]*csound[^\n]*").unwrap();
    let re_n = Regex::new(r"[ \t]*(```\n)").unwrap();
    let re_bs = Regex::new(r"<br\s*/?>").unwrap();

    for entry in std::fs::read_dir(&opcodes_folder)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue
        };

        let epath = entry.path();

        if epath.extension().and_then(|e| e.to_str()) != Some("md") { continue; }

        let ename = match epath.file_stem().and_then(|e| e.to_str()) {
            Some(name) => name.to_string(),
            None => continue
        };

        if let Some(content) = std::fs::read_to_string(&epath).ok() {
            let content = expand_includes(&content, &examples_folder);
            let content = re_csound.replace_all(&content, "\n```csound\n").to_string();
            let content = re_n.replace_all(&content, "\n```\n").to_string();
            let content = re_bs.replace_all(&content, "\n\n").to_string();

            map.insert(ename, content);
        }
    }
    Ok(map)
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
    global_temp: &mut Path, json_opcodes: &mut HashMap<String, String>, temp_manual_path: &mut PathBuf
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let temp_dir = global_temp.join(TEMP_CSOUND_MANUAL_DIR);

    let check_release_tag = utils::get_release_tag_from_github(GITHUB_LATEST_API_MANUAL).await;
    let release_tag = match check_release_tag {
        Ok(tag) => tag,
        Err(_) => "v-error".to_string() // verify prec version
    };

    let mut is_v_error = true;
    let mut manual_dir_path = temp_dir.clone();

    if release_tag != "v-error" {
        is_v_error = false;
        let dir_name = format!("csound_manual-html_{}", &release_tag);
        manual_dir_path = manual_dir_path.join(&dir_name);

        if !manual_dir_path.exists() {
            if temp_dir.exists() {
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
            }

            let _ = tokio::fs::create_dir_all(&temp_dir).await;

            let download_url = format!("{}/{}/{}", GITHUB_DOWNLOAD_BASE_MANUAL, release_tag, ASSET_NAME);
            let local_file = temp_dir.join(format!("csound_manual-html_{}.zip", release_tag));
            utils::download_from_github(&download_url, &temp_dir, &local_file).await?;

            let zip_name = format!("csound_manual-html_{}.zip", release_tag);
            let zip_archive_path = temp_dir.join(zip_name);
            let target_dir = manual_dir_path.clone();

            tokio::task::spawn_blocking(move || {
                if !target_dir.exists() { std::fs::create_dir_all(&target_dir)?; }
                utils::unzip_file(&zip_archive_path, &target_dir)
            }).await??;
        }
    }

    if is_v_error {
        manual_dir_path = utils::check_valid_resource_dir(&temp_dir, "csound_manual-html_")?;
    }

    let op_path = manual_dir_path.join(&OPCODES_MD_DIR);
    let ex_path = manual_dir_path.join(&EXAMPLES_DIR);

    if op_path.exists() {
        if let Ok(opcodes) = load_opcodes(&op_path, &ex_path) {
            *json_opcodes = opcodes;
        }
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
