use crate::utils;
use crate::parser::UserDefinedType;

use once_cell::sync::Lazy;
use regex::{ Regex, Captures };
use serde::Deserialize;
use std::{
    path::{ Path, PathBuf},
    collections::HashMap,
    time::Duration
};


pub const TEMP_CSOUND_MANUAL_DIR: &str = "temp_csound_manual";
pub const GITHUB_LATEST_API_MANUAL: &str = "https://api.github.com/repos/PasqualeMainolfi/csound_manual/releases/latest";
pub const GITHUB_DOWNLOAD_BASE_MANUAL: &str = "https://github.com/PasqualeMainolfi/csound_manual/releases/download";
pub const ASSET_NAME: &str = "csound_manual-html.zip";
pub const OPCODES_MD_DIR: &str = "csound_resources/opcodes";
pub const EXAMPLES_DIR: &str = "csound_resources/examples";
pub const OPCODES_QUERY: &str = "csound_resources/csound.json";
pub const FLAGS_QUERY: &str = "csound_resources/flags.json";
pub const MACROS_QUERY: &str = "csound_resources/macros.json";
// struct types a host registers (Cabbage), which `csound --list-structs` can't see
pub const STRUCTS_QUERY: &str = "csound_resources/structs.json";

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

static INCLUDE_EXAMPLE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"--8<--\s+"([^"]+)""#).unwrap());

fn expand_includes(content: &str, examples_folder: &Path) -> String {
    INCLUDE_EXAMPLE.replace_all(content, |cap: &Captures| {
        let cap_str = &cap[1].to_string();
        let entire_path = Path::new(cap_str);
        let Some(path) = entire_path.file_name().and_then(|f| f.to_str()) else {
            return format!("<!-- undefined includes {} -->", cap_str);
        };
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("csound-lsp")
        .build()?;

    let check_release_tag = utils::get_release_tag_from_github(&client, GITHUB_LATEST_API_MANUAL).await;
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

        let version_file = manual_dir_path.join(".version");
        let check_index = manual_dir_path.join("index.html");
        let download = if version_file.exists() {
            let saved = tokio::fs::read_to_string(&version_file).await?;
            saved != release_tag || !check_index.exists()
        } else { true };

        if download {
            if manual_dir_path.exists() {
                tokio::fs::remove_dir_all(&manual_dir_path).await?;
            }

            tokio::fs::create_dir_all(&temp_dir).await?;

            let download_url = format!("{}/{}/{}", GITHUB_DOWNLOAD_BASE_MANUAL, release_tag, ASSET_NAME);
            let local_file = temp_dir.join(format!("csound_manual-html_{}.zip", release_tag));
            utils::download_from_github(&download_url, &temp_dir, &local_file).await?;

            let zip_name = format!("csound_manual-html_{}.zip", release_tag);
            let zip_archive_path = temp_dir.join(zip_name);
            let target_dir = manual_dir_path.clone();

            std::fs::create_dir_all(&target_dir)?;
            utils::unzip_file(&zip_archive_path, &target_dir)?;
            tokio::fs::write(&version_file, release_tag).await?;
        }

    }

    if is_v_error {
        manual_dir_path = utils::check_valid_resource_dir(&temp_dir, "csound_manual-html_")?;
    }

    let op_path = manual_dir_path.join(&OPCODES_MD_DIR);
    let ex_path = manual_dir_path.join(&EXAMPLES_DIR);

    if op_path.exists() {
        // ~1300 markdown files: read them off the async runtime
        let loaded = tokio::task::spawn_blocking(move || load_opcodes(&op_path, &ex_path)).await;
        if let Ok(Ok(opcodes)) = loaded {
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

// `{ "CabbageNumTrig": { "members": [["val", "k"], ["trig", "k"]], "description": "...",
//    "opcodes": ["cabbageGetValue"], "source": "Cabbage", "doc": "https://..." } }`
#[derive(Deserialize, Debug, Clone)]
pub struct ManualStruct {
    pub members: Vec<(String, String)>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub opcodes: Vec<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub doc: Option<String>
}

impl ManualStruct {
    pub fn to_udt(&self, name: &str) -> UserDefinedType {
        let members = self.members.iter().map(|(n, t)| format!("{}:{}", n, t)).collect::<Vec<_>>().join(", ");
        let mut documentation = Vec::new();
        if !self.description.is_empty() {
            documentation.push(self.description.clone());
        }
        if !self.opcodes.is_empty() {
            let opcodes = self.opcodes.iter().map(|o| format!("`{}`", o)).collect::<Vec<_>>().join(", ");
            documentation.push(format!("**Accepted by:** {}", opcodes));
        }
        if let Some(doc) = &self.doc {
            let what = self.source.as_deref().map(|s| format!("{} documentation", s)).unwrap_or_else(|| "Documentation".to_string());
            documentation.push(format!("[{}]({})", what, doc));
        }

        let mut udt = UserDefinedType::new();
        udt.udt_name = name.to_string();
        udt.udt_format = format!("struct {} {}", name, members);
        udt.udt_members = Some(self.members.clone());
        udt.from_plugin = true;
        udt.source = self.source.clone();
        udt.documentation = (!documentation.is_empty()).then(|| documentation.join("\n\n"));
        udt
    }
}

#[derive(Debug, Default)]
pub struct CsoundJsonData {
    pub opcodes_data: Option<HashMap<String, OpcodesData>>,
    pub omacros_data: Option<HashMap<String, OMacro>>,
    pub oflag_data: Option<HashMap<String, OpcodesData>>,
    pub structs_data: HashMap<String, UserDefinedType>
}

impl CsoundJsonData {
    // The types a file can use before it defines any: the manual's host types,
    // then those listed by Csound, which win on a name clash.
    pub fn known_types(&self, plugin_types: &HashMap<String, UserDefinedType>) -> HashMap<String, UserDefinedType> {
        let mut types = self.structs_data.clone();
        types.extend(plugin_types.iter().map(|(k, v)| (k.clone(), v.clone())));
        types
    }
}

pub fn parse_manual_structs(json: &str) -> serde_json::Result<HashMap<String, UserDefinedType>> {
    let structs = serde_json::from_str::<HashMap<String, ManualStruct>>(json)?;
    Ok(structs.iter()
        .filter(|(_, s)| !s.members.is_empty())
        .map(|(name, s)| (name.clone(), s.to_udt(name)))
        .collect())
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

    // manual releases before the Cabbage structs have no such file
    let json_structs = base_dir.join(STRUCTS_QUERY);
    if let Ok(jst) = tokio::fs::read_to_string(&json_structs).await {
        match parse_manual_structs(&jst) {
            Ok(map) => cj.structs_data = map,
            Err(e) => eprintln!("ERROR: Could not parse struct JSON: {}", e)
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRUCTS: &str = r#"{
        "CabbageNumTrig": {
            "members": [["val", "k"], ["trig", "k"]],
            "description": "A value plus a trigger.",
            "opcodes": ["cabbageGetValue"],
            "source": "Cabbage",
            "doc": "https://cabbageaudio.com/docs/using/csound7/#built-in-trigger-structs"
        },
        "Empty": { "members": [] }
    }"#;

    #[test]
    fn manual_structs_become_host_types() {
        let types = parse_manual_structs(STRUCTS).unwrap();
        assert!(!types.contains_key("Empty"), "a struct without members is skipped");

        let udt = &types["CabbageNumTrig"];
        assert_eq!(udt.udt_format, "struct CabbageNumTrig val:k, trig:k");
        assert_eq!(udt.udt_members, Some(vec![("val".to_string(), "k".to_string()), ("trig".to_string(), "k".to_string())]));
        assert!(udt.from_plugin, "a struct in the file may replace it");
        assert_eq!(udt.hover_title(), "Cabbage Type");

        let doc = udt.documentation.as_deref().unwrap();
        assert!(doc.starts_with("A value plus a trigger."));
        assert!(doc.contains("`cabbageGetValue`"));
        assert!(doc.contains("[Cabbage documentation](https://cabbageaudio.com/docs/using/csound7/#built-in-trigger-structs)"));
    }

    #[test]
    fn types_listed_by_csound_win_over_the_manual() {
        let data = CsoundJsonData { structs_data: parse_manual_structs(STRUCTS).unwrap(), ..Default::default() };
        let mut listed = UserDefinedType::new();
        listed.udt_name = "CabbageNumTrig".to_string();
        listed.from_plugin = true;
        let plugin_types = HashMap::from([("CabbageNumTrig".to_string(), listed)]);

        let known = data.known_types(&plugin_types);
        assert_eq!(known["CabbageNumTrig"].hover_title(), "Plugin Type");
        assert_eq!(data.known_types(&HashMap::new())["CabbageNumTrig"].hover_title(), "Cabbage Type");
    }

    #[test]
    fn manual_structs_json_of_the_release_parses() {
        // the file the manual CI ships, when the manual checkout sits next to this repo
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../csound_data/csound_manual/parse_data_to_lsp/json_data/structs.json");
        let Ok(json) = std::fs::read_to_string(path) else { return };
        let types = parse_manual_structs(&json).unwrap();
        assert!(types.contains_key("CabbageNumTrig") && types.contains_key("CabbageStrTrig"));
    }
}
