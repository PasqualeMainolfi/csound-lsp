use rust_embed::RustEmbed;
use tower_lsp::lsp_types::{ Position, Range, Diagnostic };
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

pub fn is_diagnostic_cached(diag_key: &Diagnostic, cached_diagnostics: &mut HashSet<(u32, u32, String)>) -> bool {
    let dkey = (
        diag_key.range.start.line,
        diag_key.range.end.character,
        diag_key.message.clone()
    );
    if !cached_diagnostics.contains(&dkey) {
        cached_diagnostics.insert(dkey);
        return false;
    }
    return true;
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

pub fn is_valid_type(type_identifier: &String) -> bool {
    let trimmed = type_identifier.trim_end_matches("[]");
    match trimmed {
        "InstrDef" | "Instr" | "Opcode" | "Complex" => true,
        "a" | "i" | "k" | "S" | "f" | "w" | "b" => true,
        _ => false
    }
}

fn is_valid_output_udo_types<'a>(type_identifier: &String, node: Node<'a>) -> bool {
    let trimmed = type_identifier.trim();
    if node.kind() == "udo_definition_modern" {
        if trimmed.eq_ignore_ascii_case("void") {
            return true;
        }
    }

    let mut chars = trimmed.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            'a' | 'f' | 'i' | 'j' | 'k' | 'K' | 'S' => { },
            '[' => {
                if chars.next() != Some(']') {
                    return false
                }
            },
            _ => return false
        }
    }

    true
}

fn is_valid_input_udo_types(type_identifier: &String) -> bool {
    let trimmed = type_identifier.trim();

    let mut chars = trimmed.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            'a' | 'f' | 'i' | 'j' | 'k' | 'o' | 'p' | 'O' | 'P' | 'V' | 'J' | 'K' | 'S' | '0' => { },
            '[' => {
                if chars.next() != Some(']') {
                    return false
                }
            },
            _ => return false
        }
    }

    true
}

pub fn iterate_tree<'a>(tree: &'a Tree, text: &String, user_defined_types: &mut HashMap<String, String>) -> NodeCollects<'a> {
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
                        let node_key = node_name.clone();
                        nodes_to_diagnostics.udt.insert(node_name);

                        if !user_defined_types.contains_key(&node_key) {
                            let mut formats = Vec::new();
                            let mut cursor = node.walk();
                            for child in node.children_by_field_name("fields", &mut cursor) {
                                let child_name = child.child_by_field_name("name").and_then(|n| get_node_name(n, &text));
                                let child_type = child.child_by_field_name("type").and_then(|n| get_node_name(n, &text));

                                if let (Some(nc), Some(tc)) = (child_name, child_type) {
                                    formats.push(format!("{}:{}", nc, tc));
                                }
                            }
                            let struct_format = format!("struct {} {}", node_key, formats.join(", "));
                            user_defined_types.insert(node_key, struct_format);
                        }
                    };
                }
            },
            "legacy_udo_args" => {
                if let Some(text_content) = get_node_name(node, &text) {

                    let is_inputs_context = node.parent()
                        .and_then(|p| p.child_by_field_name("inputs"))
                        .map(|in_node| in_node.start_byte() == node.start_byte())
                        .unwrap_or(false);

                    for (_, char) in text_content.char_indices() {

                        let is_valid = if is_inputs_context {
                            match char {
                                'a'|'f'|'i'|'j'|'k'|'K'|'S'|'0'|'p'|'P'|'o'|'O'|'V'|'J'|'['|']' => true,
                                _ => false // La 'c' cade qui
                            }
                        } else {
                            match char {
                                'a'|'f'|'i'|'j'|'k'|'K'|'S'|'0'|'['|']' => true,
                                _ => false
                            }
                        };

                        if !is_valid {
                            nodes_to_diagnostics.generic_errors.push(GenericError {
                                node: node,
                                error_type: GErrors::ExplicitType,
                            });
                        }
                    }
                }
            },
            // check modern udo outputs
            "udo_definition_modern" | "udo_definition_legacy" => {
                if let Some(outputs_node) = node.child_by_field_name("outputs") {
                    let mut cursor = outputs_node.walk();
                    let children = outputs_node.children(&mut cursor).collect::<Vec<_>>();

                    let boundary = match node.kind() {
                        "udo_definition_modern" => {
                            Some((
                                children.iter().find(|n| n.kind() == "("),
                                children.iter().find(|n| n.kind() == ")")
                            ))
                        },
                        "udo_definition_legacy" => {
                            Some((
                                children.iter().find(|n| n.kind() == ","),
                                children.iter().find(|n| n.kind() == ",")
                            ))
                        },
                        _ => None
                    };

                    if let Some((b_start, b_end)) = boundary {
                        if let Some(open) = b_start {
                            let content_start_byte = open.end_byte();

                            let content_end_byte = if let Some(close) = b_end {
                                close.start_byte()
                            } else {
                                outputs_node.end_byte()
                            };

                            if content_end_byte > content_start_byte {
                                let raw_content = &text[content_start_byte..content_end_byte];
                                if raw_content != "void" {
                                    if !is_valid_output_udo_types(&raw_content.trim().to_string(), node) {
                                        nodes_to_diagnostics.generic_errors.push(GenericError {
                                            node: outputs_node,
                                            error_type: GErrors::ExplicitType,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            },
            // check ERROR node
            "ERROR" => {
                if let Some(node_name) = get_node_name(node, &text) {
                    let trim_name = node_name.trim();
                    let current_parent_kind = node.parent().unwrap().kind();
                    if current_parent_kind != "modern_udo_outputs" && (!trim_name.contains(")") && !trim_name.contains(",")) {
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
