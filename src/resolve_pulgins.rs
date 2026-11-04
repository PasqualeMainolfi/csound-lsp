#![allow(unused)]

use crate::{
    assets::{ self, OpcodesData }, utils::{ GitHubEntry, PVersion, PVersionAge, parse_plugins_git_url }
};
use std::{
    collections::{ HashMap, HashSet },
    path::{ Path, PathBuf },
    time::Duration,
    env,
    process::{ self, Stdio }
};

use serde::{Deserialize, Serialize};
use regex::Regex;


// read risset index to capture opcode docs
pub const GITHUB_RISSET_PLUGINS_INDEX: &str = "https://raw.githubusercontent.com/csound-plugins/risset-data/master/rissetindex.json"; // for raw download


const TEMP_CSOUND_PLUGINS_DIR: &str = "temp_csound_plugins";

// plugins of this repo are not in the Risset index: same layout (src/<plugin>/risset.json, doc/<opcode>.md)
const CSOUND_PLUGINS_REPO: (&str, &str) = ("csound", "plugins");
const CSOUND_PLUGINS_REPO_DIR: &str = "csound_plugins_repo";
const PLUGIN_MANIFEST: &str = "risset.json";

const LIST_OPCODES_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_LISTED_SIGNATURES: usize = 8;

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

#[derive(Deserialize)]
struct GitTree {
    tree: Vec<GitTreeEntry>
}

#[derive(Deserialize)]
struct GitTreeEntry {
    path: String
}

struct PluginDocFormat {
    csound_block: Regex,
    block_end: Regex,
    line_break: Regex
}

impl PluginDocFormat {
    fn new() -> Self {
        Self {
            csound_block: Regex::new(r"```[ \t]*csound[^\n]*").unwrap(),
            block_end: Regex::new(r"[ \t]*(```\n)").unwrap(),
            line_break: Regex::new(r"<br\s*/?>").unwrap()
        }
    }
}

// where a plugin lives and how it is shown
struct PluginSource<'a> {
    owner: &'a str,
    repo: &'a str,
    remote_path: &'a str,
    plugin_name: &'a str,
    libname: &'a str
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

async fn check_csound_env() -> Result<EnvMode, Box<dyn std::error::Error + Send + Sync>> {
    let op_system = match env::consts::OS {
        "linux" => OperativeSystem::Linux,
        "macos" => OperativeSystem::MacOs,
        "windows" => OperativeSystem::Windows,
        _ => return Err("Can't check current OS".into())
    };

    let cs_command = tokio::process::Command::new("csound")
        .arg("--version")
        .output()
        .await
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
    let env: EnvMode = check_csound_env().await?;

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

    let format = PluginDocFormat::new();

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
        let remote_path = src_path.to_string_lossy();
        let source = PluginSource { owner: &owner, repo: &repo, remote_path: &remote_path, plugin_name, libname };
        load_plugin_from_repo(&client, &source, &temp_dir, &format, None, &mut map).await?;
    }

    *plugin_opcodes = map;

    Ok(())
}

async fn load_plugin_from_repo(
    client: &reqwest::Client,
    source: &PluginSource<'_>,
    temp_dir: &Path,
    format: &PluginDocFormat,
    listed: Option<&ListedOpcodes>,
    map: &mut HashMap<String, CsoundPlugin>
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let local_plugin_dir = temp_dir.join(source.plugin_name);
    let local_plugin_doc_dir = local_plugin_dir.join("doc");
    let local_plugin_data_man = local_plugin_dir.join("data.json");

    // raw download: unlike the GitHub API it is not rate limited, and csound/plugins needs every manifest
    let manifest_url = if source.remote_path.is_empty() {
        format!(
            "https://raw.githubusercontent.com/{}/{}/HEAD/{}",
            source.owner, source.repo, PLUGIN_MANIFEST
        )
    } else {
        format!(
            "https://raw.githubusercontent.com/{}/{}/HEAD/{}/{}",
            source.owner, source.repo, source.remote_path, PLUGIN_MANIFEST
        )
    };

    let remote_opcodes_man = match client.get(manifest_url).send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(resp) => match resp.bytes().await {
                Ok(manifest_bytes) => serde_json::from_slice::<CsoundPluginOpcodes>(&manifest_bytes).ok(),
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
                Err(_) => return Ok(()),
            },
            Err(_) => return Ok(()),
        }
    };

    // with a listing, only what the installed Csound can really load counts
    let opcodes: Vec<String> = opcodes_man.opcodes
        .iter()
        .filter(|opcode| listed.map_or(true, |l| l.contains_key(*opcode)))
        .cloned()
        .collect();
    if opcodes.is_empty() { return Ok(()); }

    let version: PVersion = PVersion::new(&opcodes_man.version);

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
                        if local_pdata.opcodes == opcodes_man.opcodes && docs_are_cached {
                            should_download_docs = false;
                        }
                    },
                    PVersionAge::Oldest => { }
                }
            }
        }
    }

    if should_download_docs {
        let doc_api_url = if source.remote_path.is_empty() {
            format!(
                "https://api.github.com/repos/{}/{}/contents/doc",
                source.owner, source.repo
            )
        } else {
            format!(
                "https://api.github.com/repos/{}/{}/contents/{}/doc",
                source.owner, source.repo, source.remote_path
            )
        };

        // a failing plugin must not stop the others
        let gh_entries: Vec<GitHubEntry> = match client.get(doc_api_url).send().await {
            Ok(resp) => match resp.error_for_status() {
                Ok(resp) => resp.json().await.unwrap_or_default(),
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
                    Ok(resp) => match resp.bytes().await {
                        Ok(bytes) => bytes,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                },
                Err(_) => continue,
            };

            tokio::fs::write(local_plugin_doc_dir.join(&entry.name), &fbytes).await?;
        }

        let djson = serde_json::to_string_pretty(&opcodes_man)?;
        tokio::fs::write(&local_plugin_data_man, djson).await?;
    }

    for opcode in &opcodes {
        if map.contains_key(opcode) { continue; }

        let doc_path = local_plugin_doc_dir.join(format!("{}.md", opcode));

        let documentation = match tokio::fs::read_to_string(&doc_path).await {
            Ok(content_file) => {
                let content = format.csound_block
                    .replace_all(&content_file, "\n```csound\n")
                    .to_string();

                let content = format.block_end
                    .replace_all(&content, "\n```\n")
                    .to_string();

                format.line_break
                    .replace_all(&content, "\n\n")
                    .to_string()
            }
            Err(_) => String::new(),
        };

        map.insert(
            opcode.clone(),
            CsoundPlugin {
                libname: source.libname.to_string(),
                documentation,
            },
        );
    }

    Ok(())
}

// Plugins of csound/plugins. Folder and library names differ (hdf5 builds hdf5ops), so a
// plugin counts as installed when Csound lists one of its opcodes. Entries already known win.
pub async fn load_csound_plugins_repo_resources(
    global_temp: &Path,
    listed: &ListedOpcodes,
    plugin_opcodes: &mut HashMap<String, CsoundPlugin>
) -> Result<usize, Box<dyn std::error::Error + Sync + Send>> {
    load_plugins_of_repo(global_temp, CSOUND_PLUGINS_REPO, listed, plugin_opcodes).await
}

async fn load_plugins_of_repo(
    global_temp: &Path,
    (owner, repo): (&str, &str),
    listed: &ListedOpcodes,
    plugin_opcodes: &mut HashMap<String, CsoundPlugin>
) -> Result<usize, Box<dyn std::error::Error + Sync + Send>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("csound-lsp")
        .build()?;

    let tree: GitTree = client
        .get(format!("https://api.github.com/repos/{}/{}/git/trees/HEAD?recursive=1", owner, repo))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let temp_dir = global_temp.join(TEMP_CSOUND_PLUGINS_DIR).join(CSOUND_PLUGINS_REPO_DIR);
    let format = PluginDocFormat::new();
    let known_before = plugin_opcodes.len();

    for plugin_name in plugin_dirs_with_manifest(&tree) {
        let remote_path = format!("src/{}", plugin_name);
        let source = PluginSource { owner, repo, remote_path: &remote_path, plugin_name: &plugin_name, libname: &plugin_name };
        load_plugin_from_repo(&client, &source, &temp_dir, &format, Some(listed), plugin_opcodes).await?;
    }

    Ok(plugin_opcodes.len() - known_before)
}

fn plugin_dirs_with_manifest(tree: &GitTree) -> Vec<String> {
    tree.tree
        .iter()
        .filter_map(|entry| entry.path.strip_prefix("src/")?.strip_suffix(PLUGIN_MANIFEST)?.strip_suffix('/'))
        .filter(|dir| !dir.contains('/'))
        .map(str::to_string)
        .collect()
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

// opcode name -> (outputs, inputs), one entry per overload
pub type ListedOpcodes = HashMap<String, Vec<(String, String)>>;

// Asks the installed Csound what it can load, so plugins missing from the Risset index are known too.
pub async fn list_csound_opcodes() -> Result<ListedOpcodes, Box<dyn std::error::Error + Send + Sync>> {
    let command = tokio::process::Command::new("csound")
        .arg("--list-opcodes1")
        .stdin(Stdio::null())
        .kill_on_drop(true) // a plugin hanging while it loads must not outlive the timeout
        .output();

    let output = tokio::time::timeout(LIST_OPCODES_TIMEOUT, command)
        .await
        .map_err(|_| "csound --list-opcodes1 timed out")??;

    // Csound prints the list on stderr and always exits with an error (no orchestra name),
    // so the exit code says nothing: only the closing count line proves the list is complete.
    parse_opcode_list(&String::from_utf8_lossy(&output.stderr))
        .ok_or_else(|| "Can't parse the output of csound --list-opcodes1".into())
}

fn is_opcode_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_opcode_list(list: &str) -> Option<ListedOpcodes> {
    let mut opcodes = ListedOpcodes::new();
    for line in list.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        match columns.as_slice() {
            [count, "opcodes"] if count.chars().all(|c| c.is_ascii_digit()) => return Some(opcodes),
            [name, outputs, inputs] if is_opcode_name(name) => {
                opcodes.entry(name.to_string()).or_default().push((outputs.to_string(), inputs.to_string()));
            },
            _ => { }
        }
    }
    None
}

fn listed_opcode_description(signatures: &[(String, String)]) -> String {
    let mut description = String::from("Opcode listed by the installed Csound (outputs, inputs):");
    for (outputs, inputs) in signatures.iter().take(MAX_LISTED_SIGNATURES) {
        description.push_str(&format!("\n{} {}", outputs, inputs));
    }
    if signatures.len() > MAX_LISTED_SIGNATURES {
        description.push_str(&format!("\n... and {} more", signatures.len() - MAX_LISTED_SIGNATURES));
    }
    description
}

// Entries from the manual and from Risset are richer, so they are never replaced.
pub fn add_listed_opcodes_to_cs_references(listed: &ListedOpcodes, cs_references: &mut assets::CsoundJsonData) {
    let opdata = cs_references.opcodes_data.get_or_insert_with(HashMap::new);
    for (opcode, signatures) in listed {
        // one-letter names are type casts (B, b), not opcodes to suggest
        if opcode.len() < 2 { continue; }
        opdata.entry(opcode.clone()).or_insert_with(|| OpcodesData {
            prefix: opcode.clone(),
            body: assets::BodyOpCompletion::SingleLine(opcode.clone()),
            description: listed_opcode_description(signatures)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
B           B           k
beosc       a           akjop
beosc       a           kkjop
sid6581adsr :Sid6581ADSR; kkkk

4 opcodes

Usage:      csound [-flags] orchfile scorefile
-U unam     run utility program unam
";

    #[test]
    fn parses_overloads_and_stops_at_the_count_line() {
        let listed = parse_opcode_list(LISTING).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed["beosc"], vec![
            ("a".to_string(), "akjop".to_string()),
            ("a".to_string(), "kkjop".to_string())
        ]);
        assert_eq!(listed["sid6581adsr"], vec![(":Sid6581ADSR;".to_string(), "kkkk".to_string())]);
        assert!(!listed.contains_key("-U"), "usage text after the count must be ignored");
    }

    #[test]
    fn a_listing_without_the_count_line_is_rejected() {
        assert!(parse_opcode_list("beosc a akjop\n").is_none());
        assert!(parse_opcode_list("csound: command failed\n").is_none());
    }

    #[test]
    fn listed_opcodes_never_replace_known_ones_and_skip_casts() {
        let mut references = assets::CsoundJsonData::default();
        references.opcodes_data = Some(HashMap::from([("beosc".to_string(), OpcodesData {
            prefix: "beosc".to_string(),
            body: assets::BodyOpCompletion::SingleLine("beosc".to_string()),
            description: "from risset".to_string()
        })]));

        add_listed_opcodes_to_cs_references(&parse_opcode_list(LISTING).unwrap(), &mut references);

        let opcodes = references.opcodes_data.unwrap();
        assert_eq!(opcodes["beosc"].description, "from risset");
        assert!(opcodes["sid6581adsr"].description.contains(":Sid6581ADSR; kkkk"));
        assert!(!opcodes.contains_key("B"));
    }

    #[test]
    fn listed_opcodes_work_without_the_manual_data() {
        let mut references = assets::CsoundJsonData::default();
        add_listed_opcodes_to_cs_references(&parse_opcode_list(LISTING).unwrap(), &mut references);
        assert!(references.opcodes_data.unwrap().contains_key("beosc"));
    }

    #[test]
    fn only_direct_plugin_folders_with_a_manifest_are_kept() {
        let entries = ["README.md", "src/chips/risset.json", "src/chips/sid6581.cpp", "src/stk/doc/a.md",
                       "src/py/src/risset.json", "risset.json", "src/notrisset.json", "src/hdf5/risset.json"];
        let tree = GitTree { tree: entries.iter().map(|p| GitTreeEntry { path: p.to_string() }).collect() };
        assert_eq!(plugin_dirs_with_manifest(&tree), vec!["chips".to_string(), "hdf5".to_string()]);
    }

    // csound-plugins already has the layout expected from csound/plugins
    #[tokio::test]
    #[ignore = "needs network access"]
    async fn loads_only_listed_opcodes_of_a_repo_with_docs() {
        let temp = env::temp_dir().join(format!("csound-lsp-test-{}", process::id()));
        let listed = ListedOpcodes::from([("crackle".to_string(), vec![("a".to_string(), "P".to_string())])]);
        let mut map = HashMap::new();

        let added = load_plugins_of_repo(&temp, ("csound-plugins", "csound-plugins"), &listed, &mut map).await.unwrap();
        let _ = std::fs::remove_dir_all(&temp);

        assert_eq!(added, 1);
        assert_eq!(map["crackle"].libname, "else");
        assert!(map["crackle"].documentation.contains("# crackle"));
    }

    #[test]
    fn long_overload_lists_are_truncated() {
        let signatures = vec![("a".to_string(), "k".to_string()); MAX_LISTED_SIGNATURES + 2];
        let description = listed_opcode_description(&signatures);
        assert_eq!(description.matches("\na k").count(), MAX_LISTED_SIGNATURES);
        assert!(description.ends_with("... and 2 more"));
    }
}
