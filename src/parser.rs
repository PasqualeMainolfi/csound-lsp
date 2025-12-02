use rust_embed::RustEmbed;
use tower_lsp::lsp_types::{ Position, Range };
use tree_sitter::{ Node, Parser, Point, Tree };
use std::path::Path;
use std::collections::{HashMap, HashSet};
use tree_sitter_csound::LANGUAGE;

#[derive(RustEmbed)]
#[folder = "tree-sitter-csound/csound_manual/docs/opcodes"]
struct Asset;

pub fn parse_doc(text: &str) -> Tree {
    let mut p = Parser::new();
    let language = LANGUAGE.into();
    p.set_language(&language).unwrap();
    p.parse(text, None).unwrap()
}

fn has_ancestor_of_kind(node: Node, kind: &str) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if p.kind() == kind {
            return true;
        }
        parent = p.parent();
    }
    false
}

#[derive(Debug)]
pub enum GErrors {
    Syntax,
    ExplicitType
}

#[derive(Debug)]
pub struct GenericError<'a> {
    pub node: Node<'a>,
    pub error_type: GErrors
}

#[derive(Debug)]
pub struct NodeCollects<'a> {
    pub opcodes: Vec<Node<'a>>,
    pub udo: HashSet<String>,
    pub types: Vec<Node<'a>>,
    pub generic_errors: Vec<GenericError<'a>>,
    pub udt: HashSet<String>
}


impl<'a> NodeCollects<'a> {
    fn new() -> Self {
        Self {
            opcodes: Vec::new(),
            udo: HashSet::new(),
            types: Vec::new(),
            generic_errors: Vec::new(),
            udt: HashSet::new()
        }
    }
}

enum OpcodeCheck {
    Opcode,
    Udo
}


pub fn get_node_name<'a>(node: Node<'a>, text: &String) -> Option<String> {
    if let Ok(name) = node.utf8_text(text.as_bytes()) {
        return Some(name.to_string())
    }
    None
}

fn check_opcode<'a>(node: Node<'a>) -> Option<OpcodeCheck> {
    if node.kind() == "opcode_name" {
        if !has_ancestor_of_kind(node, "udo_definition") {
            return Some(OpcodeCheck::Opcode)
        } else {
            return Some(OpcodeCheck::Udo)
        }
    }
    None
}

pub fn is_valid_type<'a>(type_identifier: &String) -> bool {
    let trimmed = type_identifier.trim_end_matches("[]");
    match trimmed {
        "InstrDef" | "Instr" | "Opcode" | "Complex" => true,
        "a" | "i" | "k" | "S" | "f" | "w" | "b" => true,
        _ => false
    }
}

pub fn iterate_tree<'a>(tree: &'a Tree, text: &String) -> NodeCollects<'a> {
    let root_node = tree.root_node().walk();
    let mut to_visit = vec![root_node.node()];
    let mut nodes_to_diagnostics = NodeCollects::new();

    while let Some(node) = to_visit.pop() {

        // check opcodes
        match check_opcode(node) {
            Some(OpcodeCheck::Opcode) => {
                nodes_to_diagnostics.opcodes.push(node);
            },
            Some(OpcodeCheck::Udo) => {
                if let Some(node_name) = get_node_name(node, &text) {
                    nodes_to_diagnostics.udo.insert(node_name);
                }
            }
            None => {}
        }

        match node.kind() {
            // check types
            "typed_identifier" => {
                if let Some(node_explicit_type) = node.child_by_field_name("type") {
                    if node_explicit_type.kind() == "identifier" {
                        nodes_to_diagnostics.types.push(node_explicit_type);
                    }
                };
            },
            // check user defined types
            "struct_definition" => {
                if let Some(node_type) = node.child_by_field_name("name") {
                    if let Some(node_name) = get_node_name(node_type, &text) {
                        nodes_to_diagnostics.udt.insert(node_name);
                    };
                }
            }
            // check ERROR node
            "ERROR" => {
                if let Some(node_name) = get_node_name(node, &text) {
                    let trim_name = node_name.trim();
                    if trim_name.len() == 1 || trim_name.contains(":") {
                        nodes_to_diagnostics.generic_errors.push(GenericError {
                                node: node,
                                error_type: GErrors::ExplicitType
                            }
                        );
                    } else {
                        nodes_to_diagnostics.generic_errors.push(GenericError {
                                node: node,
                                error_type: GErrors::Syntax
                            }
                        );
                    }
                }
            },
            _ => {}
        };

        let mut child = node.walk();
        for _ in 0..node.child_count() {
            if child.goto_first_child() {
                to_visit.push(child.node());
                child.goto_parent();
            }
        }
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i) {
                to_visit.push(c);
            }
        }
    }
    nodes_to_diagnostics
}

pub fn get_node_range(node: &Node) -> Range {
    let start = node.start_position();
    let end = node.end_position();

    Range {
        start: Position {
            line: start.row as u32,
            character: start.column as u32
        },
        end: Position {
            line: end.row as u32,
            character: end.column as u32
        }
    }
}

pub fn find_node_at_position<'a>(tree: &'a Tree, pos: &Position) -> Option<Node<'a>> {
    let row = pos.line as usize;
    let col = pos.character as usize;

    tree.root_node().descendant_for_point_range(
        Point::new(row, col),
        Point::new(row, col),
    )
}

pub fn load_opcodes() -> HashMap<String, String> {
    let mut map = HashMap::new();

    for file_path in Asset::iter() {
        let file_name = file_path.as_ref();
        if file_name.ends_with(".md") {
            let name = Path::new(file_name)
                .file_stem().and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();

            if let Some(content_file) = Asset::get(file_name) {
                if let Ok(content_str) = std::str::from_utf8(content_file.data.as_ref()) {
                    map.insert(name, content_str.to_string());
                }
            }
        }
    }
    map
}
