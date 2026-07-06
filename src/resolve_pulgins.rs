#![allow(unused)]

use crate::{
    assets::{ self, OpcodesData }, utils::{ GitHubEntry, PVersion, PVersionAge, parse_plugins_git_url }
};
use std::{
    collections::{ HashMap, HashSet },
    path::{ Path, PathBuf },
    time::Duration,
    env,
    process
};

use serde::{Deserialize, Serialize};
use regex::Regex;


// read risset index to capture opcode docs
pub const GITHUB_RISSET_PLUGINS_INDEX: &str = "https://raw.githubusercontent.com/csound-plugins/risset-data/master/rissetindex.json"; // for raw download


const TEMP_CSOUND_PLUGINS_DIR: &str = "temp_csound_plugins";

#[derive(Deserialize)]
struct RissetIndex {
    version: String,
    plugins: HashMap<String, RPlugin>
}

#[derive(Debug, Deserialize)]
struct RPlugin {
    url: String,
    path: Option<String>
}

#[derive(Debug)]
pub struct CsoundPlugin {
    pub libname: String,
    pub documentation: String
}

#[derive(Deserialize, Serialize, Debug)]
struct CsoundPluginOpcodes {
    #[serde(default)]
    version: String,
    opcodes: Vec<String>,
}

enum OperativeSystem {
    Linux,
    MacOs,
    Windows
}

enum CsoundVersion {
    Six,
    Seven
}

struct EnvMode {
    pub op_system: OperativeSystem,
    pub cs_version: CsoundVersion
}

fn check_csound_env() -> Result<EnvMode, Box<dyn std::error::Error + Send + Sync>> {
    let op_system = match env::consts::OS {
        "linux" => OperativeSystem::Linux,
        "macos" => OperativeSystem::MacOs,
        "windows" => OperativeSystem::Windows,
        _ => return Err("Can't check current OS".into())
    };

    let cs_command = process::Command::new("csound")
        .arg("--version")
        .output()
        .map_err(Box::new)?;

    let cstring = String::from_utf8_lossy(&cs_command.stderr);
    let version = cstring
        .lines()
        .find(|l| l.contains("version"))
        .and_then(|line| line.split_whitespace().find(|w| w.contains('.')))
        .and_then(|v| v.split('.').next())
        .and_then(|v| v.parse::<u8>().ok())
        .ok_or(format!("Can't parse Csound version from {:?}", &cs_command.stderr))?;

    let cs_version = match version {
        6 => CsoundVersion::Six,
        7 => CsoundVersion::Seven,
        _ => return Err("Unsupported Csound version".into())
    };

    Ok(EnvMode { op_system, cs_version })

}

fn resolve_plugins_env_path_linux(cs_version: CsoundVersion) -> Option<PathBuf> {
    let home = env::var_os("HOME").map(PathBuf::from);
    if let Some(h) = home {
        let h = h.join(".local").join("bin").join("csound");
        match cs_version {
            CsoundVersion::Six => {
                let pbuf = h.join("6.0").join("plugins64");
                return Some(pbuf)
            },
            CsoundVersion::Seven => {
                let pbuf = h.join("7.0").join("plugins64");
                return Some(pbuf)
            }
        }
    }
    None
}

fn resolve_plugins_env_path_macos(cs_version: CsoundVersion) -> Option<PathBuf> {
    let home = env::var_os("HOME").map(PathBuf::from);
    if let Some(h) = home {
        let h = h.join("Library").join("csound");
        match cs_version {
            CsoundVersion::Six => {
                let pbuf = h.join("6.0").join("plugins64");
                return Some(pbuf)
            },
            CsoundVersion::Seven => {
                let pbuf = h.join("7.0").join("plugins64");
                return Some(pbuf)
            }
        }
    }
    None
}

fn resolve_plugins_env_path_windows(cs_version: CsoundVersion) -> Option<PathBuf> {
    let home = env::var_os("USERPROFILE").map(PathBuf::from);
    if let Some(h) = home {
        let h = h.join("AppData").join("Local").join("csound");
        match cs_version {
            CsoundVersion::Six => {
                let pbuf = h.join("6.0").join("plugins64");
                return Some(pbuf)
            },
            CsoundVersion::Seven => {
                let pbuf = h.join("7.0").join("plugins64");
                return Some(pbuf)
            }
        }
    }
    None
}

pub async fn find_installed_plugins() -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
    let env: EnvMode = check_csound_env()?;

    let (path, ext) = match env.op_system {
        OperativeSystem::Linux => {
            match env.cs_version {
                CsoundVersion::Six => {
                    (resolve_plugins_env_path_linux(CsoundVersion::Six), "so")
                },
                CsoundVersion::Seven => {
                    (resolve_plugins_env_path_linux(CsoundVersion::Seven), "so")
                }
            }
        },
        OperativeSystem::MacOs => {
            match env.cs_version {
                CsoundVersion::Six => {
                    (resolve_plugins_env_path_macos(CsoundVersion::Six), "dylib")
                },
                CsoundVersion::Seven => {
                    (resolve_plugins_env_path_macos(CsoundVersion::Seven), "dylib")
                }
            }
        },
        OperativeSystem::Windows => {
            match env.cs_version {
                CsoundVersion::Six => {
                    (resolve_plugins_env_path_windows(CsoundVersion::Six), "dll")
                },
                CsoundVersion::Seven => {
                    (resolve_plugins_env_path_windows(CsoundVersion::Seven), "dll")
                }
            }
        }
    };

    let path = path.ok_or("Plugins environment path could be not resolved!")?;
    if !path.exists() {
        return Err(format!("Plugins path does not exists: {}", path.display()).into());
    }

    let mut plugins = HashSet::new();
    for entry in std::fs::read_dir(&path)? {

        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue
        };

        let plug_path = entry.path();
        if plug_path.extension().and_then(|e| e.to_str()) == Some(ext) {
            let pname = plug_path.file_name().unwrap().to_string_lossy().to_string();
            plugins.insert(pname);
        }
    }

    return Ok(plugins)
}


pub async fn load_plugins_resources(
    global_temp: &mut Path,
    installed_plugins: &HashSet<String>,
    plugin_opcodes: &mut HashMap<String, CsoundPlugin>
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {

    let temp_dir = global_temp.join(TEMP_CSOUND_PLUGINS_DIR);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("csound-lsp")
        .build()?;

    let pjson: RissetIndex = client
        .get(GITHUB_RISSET_PLUGINS_INDEX)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    tokio::fs::create_dir_all(&temp_dir).await?;

    let re_csound = Regex::new(r"```[ \t]*csound[^\n]*").unwrap();
    let re_n = Regex::new(r"[ \t]*(```\n)").unwrap();
    let re_bs = Regex::new(r"<br\s*/?>").unwrap();

    let mut map = HashMap::new();

    for (plugin_name, pvalue) in &pjson.plugins {
        let libplugin = installed_plugins
            .iter()
            .map(|lib| {
                let pname = lib
                    .strip_suffix(".dylib")
                    .or_else(|| lib.strip_suffix(".so"))
                    .or_else(|| lib.strip_suffix(".dll"))
                    .unwrap_or(lib);

                let pname = pname.strip_prefix("lib").unwrap_or(pname);

                (lib, pname)
            })
            .find(|(_, pname)| *pname == plugin_name);

        let Some((libname, _)) = libplugin else { continue; };

        let (owner, repo) = match parse_plugins_git_url(&pvalue.url) {
            Ok((o, r)) => (o, r),
            Err(_) => continue,
        };

        let src_path = pvalue.path.as_ref().map(PathBuf::from).unwrap_or_default();
        let remote_plugin_path = src_path.to_string_lossy();
        let local_plugin_dir = temp_dir.join(plugin_name);
        let local_plugin_doc_dir = local_plugin_dir.join("doc");
        let local_plugin_data_man = local_plugin_dir.join("data.json");

        let manifest_api_url = if remote_plugin_path.is_empty() {
            format!(
                "https://api.github.com/repos/{}/{}/contents/risset.json",
                owner, repo
            )
        } else {
            format!(
                "https://api.github.com/repos/{}/{}/contents/{}/risset.json",
                owner, repo, remote_plugin_path
            )
        };

        let remote_opcodes_man = match client.get(manifest_api_url).send().await {
            Ok(resp) => match resp.error_for_status() {
                Ok(resp) => match resp.json::<GitHubEntry>().await {
                    Ok(manifest_entry) => {
                        if let Some(manifest_download_url) = manifest_entry.download_url {
                            match client.get(manifest_download_url).send().await {
                                Ok(resp) => match resp.error_for_status() {
                                    Ok(resp) => match resp.bytes().await {
                                        Ok(manifest_bytes) => serde_json::from_slice::<CsoundPluginOpcodes>(&manifest_bytes).ok(),
                                        Err(_) => None,
                                    },
                                    Err(_) => None,
                                },
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    },
                    Err(_) => None,
                },
                Err(_) => None,
            },
            Err(_) => None,
        };

        let opcodes_man = match remote_opcodes_man {
            Some(m) => m,
            None => match tokio::fs::read_to_string(&local_plugin_data_man).await {
                Ok(f) => match serde_json::from_str::<CsoundPluginOpcodes>(&f) {
                    Ok(m) => m,
                    Err(_) => continue,
                },
                Err(_) => continue,
            }
        };

        let version: PVersion = PVersion::new(&opcodes_man.version);
        let opcodes = &opcodes_man.opcodes;

        tokio::fs::create_dir_all(&local_plugin_dir).await?;

        let mut should_download_docs = true;
        if local_plugin_data_man.exists() && local_plugin_data_man.is_file() {
            if let Ok(f) = tokio::fs::read_to_string(&local_plugin_data_man).await {
                if let Ok(local_pdata) = serde_json::from_str::<CsoundPluginOpcodes>(&f) {
                    let local_version = PVersion::new(&local_pdata.version);
                    match local_version.compare(&version) {
                        PVersionAge::Newest | PVersionAge::Same => {
                            let docs_are_cached = opcodes.iter().all(|opcode| {
                                local_plugin_doc_dir.join(format!("{}.md", opcode)).is_file()
                            });
                            if local_pdata.opcodes == *opcodes && docs_are_cached {
                                should_download_docs = false;
                            }
                        },
                        PVersionAge::Oldest => { }
                    }
                }
            }
        }

        if should_download_docs {
            let doc_api_url = if remote_plugin_path.is_empty() {
                format!(
                    "https://api.github.com/repos/{}/{}/contents/doc",
                    owner, repo
                )
            } else {
                format!(
                    "https://api.github.com/repos/{}/{}/contents/{}/doc",
                    owner, repo, remote_plugin_path
                )
            };

            let gh_entries: Vec<GitHubEntry> = match client.get(doc_api_url).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(resp) => resp.json().await?,
                    Err(_) => Vec::new(),
                },
                Err(_) => Vec::new(),
            };

            if !gh_entries.is_empty() {
                if local_plugin_doc_dir.exists() {
                    let _ = tokio::fs::remove_dir_all(&local_plugin_doc_dir).await;
                }
                tokio::fs::create_dir_all(&local_plugin_doc_dir).await?;
            }

            for entry in gh_entries {
                if entry.kind != "file" { continue; }

                let is_md = Path::new(&entry.name)
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("md"));

                if !is_md { continue; }
                let Some(download_url) = entry.download_url else { continue; };

                let fbytes = match client.get(download_url).send().await {
                    Ok(resp) => match resp.error_for_status() {
                        Ok(resp) => resp.bytes().await?,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };

                tokio::fs::write(local_plugin_doc_dir.join(&entry.name), &fbytes).await?;
            }

            let djson = serde_json::to_string_pretty(&opcodes_man)?;
            tokio::fs::write(&local_plugin_data_man, djson).await?;
        }

        for opcode in opcodes {
            if map.contains_key(opcode) { continue; }

            let doc_path = local_plugin_doc_dir.join(format!("{}.md", opcode));

            let documentation = match tokio::fs::read_to_string(&doc_path).await {
                Ok(content_file) => {
                    let content = re_csound
                        .replace_all(&content_file, "\n```csound\n")
                        .to_string();

                    let content = re_n
                        .replace_all(&content, "\n```\n")
                        .to_string();

                    re_bs
                        .replace_all(&content, "\n\n")
                        .to_string()
                }
                Err(_) => String::new(),
            };

            map.insert(
                opcode.clone(),
                CsoundPlugin {
                    libname: libname.clone(),
                    documentation,
                },
            );
        }
    }

    *plugin_opcodes = map;

    Ok(())
}

pub async fn add_plugins_to_cs_references(plugins: &HashMap<String, CsoundPlugin>, cs_references: &mut assets::CsoundJsonData) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let opdata = cs_references.opcodes_data.as_mut().ok_or("Internal opcode cache corrupted!")?;
    for (opcode, value) in plugins.iter() {
        if let None = opdata.get(opcode) {
            opdata.insert(opcode.clone(), OpcodesData {
                prefix: opcode.clone(),
                body: assets::BodyOpCompletion::SingleLine(opcode.clone()),
                description: format!("plugin opcode from {}", value.libname)
            });
        }
    }
    Ok(())
}
