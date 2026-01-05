use tree_sitter::Parser;
use tower_lsp::lsp_types::Url;
use crate::parser::{self, UserDefinedType, UserDefinedMacro };

use std::{
    collections::{HashMap, HashSet},
    hash::{ DefaultHasher, Hash, Hasher },
    path::{ Path, PathBuf }
};


#[derive(Debug, Clone)]
pub struct UdoFile {
    pub path: PathBuf,
    pub content: Option<String>,
    pub content_hash: Option<u64>,
    pub user_defined_opcodes: HashMap<String, String>,
    pub user_defined_types: HashMap<String, UserDefinedType>,
    pub user_defined_macros: HashMap<String, UserDefinedMacro>,
    pub udo_list: HashSet<String>,
    pub type_list: HashSet<String>,
    pub macro_list: HashSet<String>
}

impl UdoFile {
    pub fn new(ufile_path: impl AsRef<Path>, uri: Url) -> Self {
        let bdir = uri.to_file_path().unwrap();
        let base_dir = bdir
            .parent()
            .unwrap();

        let pfile = ufile_path.as_ref();
        let full_path = if pfile.is_absolute() {
            pfile.to_path_buf()
        } else {
            base_dir.join(pfile)
        };

        let bytes = std::fs::read(&full_path).ok();
        let mut content: Option<String> = None;
        let mut h: Option<u64> = None;
        if let Some(c) = bytes {
            let mut hasher = DefaultHasher::new();
            c.hash(&mut hasher);
            h = Some(hasher.finish());
            content = String::from_utf8(c).ok();
        }

        Self {
            path: full_path,
            content,
            content_hash: h,
            user_defined_opcodes: HashMap::new(),
            user_defined_types: HashMap::new(),
            user_defined_macros: HashMap::new(),
            udo_list: HashSet::new(),
            type_list: HashSet::new(),
            macro_list: HashSet::new()
        }
    }

    pub fn iterate_included_udo_file(&mut self, parser: &mut Parser) -> Result<(), String> {
        if let Some(ref text) = self.content {
            let udo_tree = parser.parse(text.as_str(), None).unwrap();
            let mut user_definitions = parser::UserDefinitions::new();
            let mut udo_list = HashSet::new();
            let mut type_list = HashSet::new();

            let root = udo_tree.root_node().walk();
            let mut to_visit = vec![root.node()];
            let mut macro_list = HashSet::new();

            while let Some(node) = to_visit.pop() {
                let nkind = node.kind();
                match nkind {
                    "udo_definition_legacy" | "udo_definition_modern" => {
                        if let Some(node_name) = node.child_by_field_name("name") {
                            if let Some(op_name) = parser::get_node_name(node_name, text) {
                                let node_key = op_name.clone();
                                user_definitions.add_udo(node, &node_key, text);
                                udo_list.insert(node_key);
                            }
                        }
                    },
                    "struct_definition" => {
                        if let Some(node_type) = node.child_by_field_name("struct_name") {
                            if let Some(node_name) = parser::get_node_name(node_type, text) {
                                let node_key = node_name.clone();
                                user_definitions.add_udt(node, &node_key, text);
                                type_list.insert(node_key);
                            };
                        }
                    },
                    "macro_define" => {
                        if let Some(macro_name) = node.child_by_field_name("macro_name") {
                            if let Some(macro_name_text) = parser::get_node_name(macro_name, text) {
                                if let Some(macro_id) = macro_name.child_by_field_name("id") {
                                    let mid = parser::get_node_name(macro_id, &text).unwrap_or_default();
                                    if let Some(values) = node.child_by_field_name("macro_values") {
                                        let mv = parser::get_node_name(values, &text).unwrap_or_default();

                                        user_definitions.user_defined_macros
                                            .entry(mid.clone())
                                            .and_modify(|m| {
                                                m.node_location = node.start_byte();
                                                m.macro_label = macro_name_text.clone();
                                                m.macro_values = mv.clone();
                                            })
                                            .or_insert_with(|| UserDefinedMacro {
                                                node_location: node.start_byte(),
                                                macro_name: mid.clone(),
                                                macro_label: macro_name_text.clone(),
                                                macro_values: mv.clone()
                                            });

                                        macro_list.insert(mid);

                                    }
                                }
                            }
                        }
                    },
                    _ => { }
                }

                for i in (0..node.child_count()).rev() {
                    if let Some(c) = node.child(i) {
                        to_visit.push(c);
                    }
                }
            }

            self.user_defined_opcodes = user_definitions.user_defined_opcodes.clone();
            self.user_defined_types = user_definitions.user_defined_types.clone();
            self.user_defined_macros = user_definitions.user_defined_macros.clone();
            self.udo_list = udo_list;
            self.type_list = type_list;
            self.macro_list = macro_list;
        } else {
            return Err(format!("Impossible to parse .udo file. Content corrupted: {:#?} {:?}", self.path, self.content))
        }
        Ok(())
    }
}
