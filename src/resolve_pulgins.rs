use crate::{
    assets::{self, OpcodesData},
    utils
};
use std::{
    collections::{ HashMap, HashSet }, env, path::{ Path, PathBuf }, process
};
use serde::Deserialize;
use regex::Regex;

const TEMP_CSOUND_PLUGINS_DIR: &str = "temp_csound_plugins";
pub const GITHUB_LATEST_API_PLUGINS: &str = "https://api.github.com/repos/csound-plugins/csound-plugins/releases/latest";
pub const GITHUB_DOWNLOAD_BASE_PLUGINS: &str = "https://github.com/csound-plugins/csound-plugins/archive/refs/tags";


#[derive(Debug)]
pub struct CsoundPlugin {
    pub libname: String,
    pub documentation: String
}

#[derive(Deserialize, Debug)]
struct CsoundPluginOpcodes {
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
    global_temp: &mut Path, installed_plugins: &HashSet<String>, plugin_opcodes: &mut HashMap<String, CsoundPlugin>
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let temp_dir = global_temp.join(TEMP_CSOUND_PLUGINS_DIR);

    let check_release_tag = utils::get_release_tag_from_github(GITHUB_LATEST_API_PLUGINS).await;
    let release_tag = match check_release_tag {
        Ok(tag) => tag,
        Err(_) => "v-error".to_string() // verify prec version
    };

    let mut is_v_error = true;
    let mut plugins_dir_path = temp_dir.clone();

    if release_tag != "v-error" {
        is_v_error = false;

        let dir_name = format!("csound-plugins_{}", &release_tag);
        plugins_dir_path = plugins_dir_path.join(&dir_name);

        if !plugins_dir_path.exists() {
            if temp_dir.exists() {
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
            }

            let _ = tokio::fs::create_dir_all(&temp_dir).await;

            let download_url = format!("{}/{}.zip", GITHUB_DOWNLOAD_BASE_PLUGINS, release_tag);
            let local_file = temp_dir.join(format!("csound-plugins_{}.zip", release_tag));
            utils::download_from_github(&download_url, &temp_dir, &local_file).await?;

            let zip_name = format!("csound-plugins_{}.zip", release_tag);
            let zip_archive_path = temp_dir.join(zip_name);
            let target_dir = plugins_dir_path.clone();

            if !target_dir.exists() { std::fs::create_dir_all(&target_dir)?; }
            utils::unzip_file(&zip_archive_path, &target_dir)?;

            let mut entries = tokio::fs::read_dir(&plugins_dir_path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let epath = entry.path();
                if epath.is_dir() {
                    if let Some(fname) = epath.file_name().and_then(|n| n.to_str()) {
                        if fname.starts_with("csound-plugins-") {
                            utils::copy_dir_recursively(&epath, &plugins_dir_path).await?;
                            tokio::fs::remove_dir_all(&epath).await?;
                        }
                    }
                }
            }
        }
    }

    if is_v_error  {
        plugins_dir_path = utils::check_valid_resource_dir(&temp_dir, "csound-plugins_")?;
    }

    let docs_path = plugins_dir_path.join("docs");
    let op_path = docs_path.join("opcodes");
    let src_path = plugins_dir_path.join("src");

    if op_path.exists() && src_path.exists() {
        let plug_opcodes = load_plugins_opcodes(&src_path, &op_path, &installed_plugins)?;
        *plugin_opcodes = plug_opcodes;
    } else {
        return Err(format!("Plugins dir path not founded {:?}", plugins_dir_path).into());
    }

    Ok(())
}

fn load_plugins_opcodes(src_path: &Path, opcodes_path: &Path, installed_plugins: &HashSet<String>) -> std::io::Result<HashMap<String, CsoundPlugin>> {
    let mut map = HashMap::new();

    let re_csound = Regex::new(r"```[ \t]*csound[^\n]*").unwrap();
    let re_n = Regex::new(r"[ \t]*(```\n)").unwrap();
    let re_bs = Regex::new(r"<br\s*/?>").unwrap();

    for entry in std::fs::read_dir(&src_path)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue
        };

        let epath = entry.path();

        if !epath.is_dir() || !epath.join("risset.json").exists() { continue; }

        let manifest_file = epath.join("risset.json");
        let fname = epath.file_name().and_then(|f| f.to_str()).unwrap_or("");

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
            .find(|lib| {
                lib.1 == fname
            });

        let Some((libname, _)) = libplugin else { continue };

        let m = match std::fs::read_to_string(&manifest_file) {
            Ok(readed) => readed,
            Err(_) => continue
        };

        let popcodes = match serde_json::from_str::<CsoundPluginOpcodes>(&m) {
            Ok(ops) => ops.opcodes,
            Err(_) => continue
        };

        for opcode in popcodes.iter() {
            if !map.contains_key(opcode) {
                let doc_path = opcodes_path.join(format!("{}.md", opcode));
                let doc = std::fs::read_to_string(&doc_path).ok();

                let pdoc = match doc {
                    Some(content_file) => {
                        let content = re_csound.replace_all(&content_file, "\n```csound\n").to_string();
                        let content = re_n.replace_all(&content, "\n```\n").to_string();
                        let content = re_bs.replace_all(&content, "\n\n").to_string();
                        content
                    },
                    None => String::from("")
                };

                map.insert(
                    opcode.clone(),
                    CsoundPlugin { libname: libname.clone(), documentation: pdoc }
                );
            }
        }
    }
    Ok(map)
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
