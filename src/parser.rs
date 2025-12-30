#![allow(unused)]

use regex::{ Regex, Captures };

use rust_embed::{ EmbeddedFile, RustEmbed };
use tower_lsp::lsp_types::lsif::ItemKind;
use tower_lsp::lsp_types::{
    Position,
    Range,
    Diagnostic,
    SemanticTokenType,
    SemanticToken,
    SemanticTokensResult,
    SemanticTokens,
    SemanticTokensLegend,
    SemanticTokenModifier
};

use tree_sitter::{ Node, Parser, Point, Tree, Query, QueryCursor, StreamingIterator };
use std::fmt::{ Display, Formatter };
use std::{fmt, fs};
use std::path::Path;
use std::collections::{ HashMap, HashSet };
use serde::Deserialize;
use tree_sitter_python;
use tree_sitter_html;
use tree_sitter_csound::{ LANGUAGE, INJECTIONS_QUERY, HIGHLIGHTS_QUERY };
use crate::utils::{ SEMANTIC_TOKENS, OMACROS, OPEN_BLOCKS, CLOSE_BLOCKS };

pub fn get_token_lengend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: SEMANTIC_TOKENS.to_vec(),
        token_modifiers: vec![SemanticTokenModifier::DECLARATION]
    }
}

#[derive(RustEmbed)]
#[folder = "csound_data"]
struct AssetCsoundOpcodeCompletion;

#[derive(RustEmbed)]
#[folder = "csound_data/opcodes"]
struct AssetCsoundOpcodeReferences;

#[derive(RustEmbed)]
#[folder = "csound_data/examples"]
struct AssetCsoundOpcodeExamples;

#[derive(RustEmbed)]
#[folder = "csound_data/csound_reference_manual"]
struct AssetCsoundManual;

pub struct ExternalQuery {
    pub parser: Parser,
    pub query: Query
}

pub struct ParsedTree {
    pub tree: Tree,
    pub query: Query,
    pub query_injection: Query,
    pub query_py: Query,
    pub query_html: Query,
    pub csound_parser: Parser,
    pub py_parser: Parser,
    pub html_parser: Parser
}

pub fn parse_doc(text: &str) -> ParsedTree {
    let mut p = Parser::new();
    let language = LANGUAGE.into();
    p.set_language(&language).unwrap();
    let query = Query::new(&LANGUAGE.into(), HIGHLIGHTS_QUERY).unwrap();
    let query_injection = Query::new(&LANGUAGE.into(), INJECTIONS_QUERY).unwrap();

    let mut py = Parser::new();
    let py_language = tree_sitter_python::LANGUAGE.into();
    py.set_language(&py_language).unwrap();
    let query_py = Query::new(&tree_sitter_python::LANGUAGE.into(), tree_sitter_python::HIGHLIGHTS_QUERY).unwrap();

    let mut html = Parser::new();
    let html_language = tree_sitter_html::LANGUAGE.into();
    html.set_language(&html_language).unwrap();
    let query_html = Query::new(&tree_sitter_html::LANGUAGE.into(), tree_sitter_html::HIGHLIGHTS_QUERY).unwrap();
    ParsedTree {
        tree: p.parse(text, None).unwrap(),
        query,
        query_injection,
        query_py,
        query_html,
        csound_parser: p,
        py_parser: py,
        html_parser: html
    }
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

#[derive(Debug)]
pub struct CsoundJsonData {
    pub opcodes_data: Option<HashMap<String, OpcodesData>>,
    pub omacros_data: Option<HashMap<String, OMacro>>,
    pub oflag_data: Option<HashMap<String, OpcodesData>>
}

fn open_json_data(data: &str) -> Option<EmbeddedFile> {
    match AssetCsoundOpcodeCompletion::get(data) {
        Some(c) => Some(c),
        None => None
    }
}

pub fn read_csound_json_data() -> CsoundJsonData {
    let mut cj: CsoundJsonData = CsoundJsonData {
        opcodes_data: None,
        omacros_data: None,
        oflag_data: None
    };

    let opfile = open_json_data("csound.json");
    let omfile = open_json_data("omacro.json");
    let offile = open_json_data("oflag.json");

    if let Some(f) = opfile {
        let content = std::str::from_utf8(f.data.as_ref()).unwrap_or("");
        cj.opcodes_data = match serde_json::from_str::<HashMap<String, OpcodesData>>(&content) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("ERROR: Could not parse opcode JSON: {}", e);
                None
            }
        };
    }

    if let Some(f) = omfile {
        let content = std::str::from_utf8(f.data.as_ref()).unwrap_or("");
        cj.omacros_data = match serde_json::from_str::<HashMap<String, OMacro>>(&content) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("ERROR: Could not parse omacro JSON: {}", e);
                None
            }
        };
    }

    if let Some(f) = offile {
        let content = std::str::from_utf8(f.data.as_ref()).unwrap_or("");
        cj.oflag_data = match serde_json::from_str::<HashMap<String, OpcodesData>>(&content) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("ERROR: Could not parse flag JSON: {}", e);
                None
            }
        };
    }

    cj
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
    ExplicitType,
    ScoreStatement,
    MissingPfield
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
    pub udt: HashSet<String>,
    pub typed_vars: HashMap<String, String>,
    pub user_definitions: UserDefinitions,
}

impl<'a> NodeCollects<'a> {
    fn new() -> Self {
        Self {
            opcodes: Vec::new(),
            udo: HashSet::new(),
            types: Vec::new(),
            generic_errors: Vec::new(),
            udt: HashSet::new(),
            typed_vars: HashMap::new(),
            user_definitions: UserDefinitions::new(),
        }
    }
}

enum OpcodeCheck {
    Opcode,
    Udo
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum Scope {
    Instr(String),
    Udo(String),
    Score,
    Global
}

#[derive(Debug, PartialEq)]
pub enum AccessVariableType {
    Read,
    Write,
    Update
}

#[derive(Debug)]
pub struct UserDefinedType {
    pub udt_name: String,
    pub udt_format: String,
    pub udt_members: Option<Vec<(String, String)>>,
}

impl UserDefinedType {
    pub fn new() -> Self {
        Self {
            udt_name: String::new(),
            udt_format: String::new(),
            udt_members: None
        }
    }
}

impl Display for UserDefinedType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} {}", self.udt_name, self.udt_format)?;
        if let Some(ref members) = self.udt_members {
            for member in members {
                write!(f, "{}:{}", member.0, member.1)?;
            }
        } else {
            write!(f, "No members")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UserDefinedVariable {
    pub node_location: usize,
    pub var_name: String,
    pub var_scope: Scope,
    pub var_calls: usize,
    pub is_undefined: bool,
    pub is_unused: bool,
    pub references: Vec<Range>
}

// fn get_vtype(kind: &String) -> String {

// }

#[derive(Debug, Clone)]
pub struct UserDefinedMacro {
    pub node_location: usize,
    pub macro_name: String,
    pub macro_label: String,
    pub macro_values: String
}

#[derive(Debug)]
pub struct UserDefinitions {
    pub user_defined_types: HashMap<String, UserDefinedType>,
    pub user_defined_opcodes: HashMap<String, String>,
    pub user_defined_macros: HashMap<String, UserDefinedMacro>,
    pub undefined_vars: Vec<UserDefinedVariable>,
    pub unused_vars: Vec<UserDefinedVariable>,
    local_defined_vars: HashMap<Scope, HashMap<String, UserDefinedVariable>>,
    global_defined_vars: HashMap<String, UserDefinedVariable>,
}

impl UserDefinitions {
    pub fn new() -> Self {
        Self {
            user_defined_types: HashMap::new(),
            user_defined_opcodes: HashMap::new(),
            user_defined_macros: HashMap::new(),
            undefined_vars: Vec::new(),
            unused_vars: Vec::new(),
            local_defined_vars: HashMap::new(),
            global_defined_vars: HashMap::new()
        }
    }

    fn update_var_use<'a>(node: Node<'a>, map: &mut HashMap<String, UserDefinedVariable>, k: &String, acc: &AccessVariableType) -> bool {
        let node_range = get_node_range(&node);
        if let Some(var) = map.get_mut(k) {
            var.var_calls += 1;
            match acc {
                AccessVariableType::Read => {
                    var.is_unused = false;
                    if var.is_undefined { var.references.push(node_range); }
                },
                AccessVariableType::Write => {
                    var.is_undefined = false;
                    var.node_location = node.start_byte();
                }
                AccessVariableType::Update => {
                    var.is_unused = false;
                    if var.is_undefined { var.references.push(node_range); }
                    var.is_undefined = false;
                }
            }
            return true;
        }
        false
    }

    pub fn add_udv<'a>(&mut self, node: Node<'a>, key: &String, text: &String) {
        let physical_scope = find_scope(node, text);
        let access_type = get_access_type(node, text);

        let parent = node.parent();
        let pkind = parent.map(|p| p.kind()).unwrap_or("");

        let is_global_syntax = pkind == "global_typed_identifier";
        // let is_typed_local_def = pkind == "typed_identifier";

        let preferred_scope = if self.global_defined_vars.contains_key(key) {
            Scope::Global
        } else if is_global_syntax || physical_scope == Scope::Global {
            Scope::Global
        } else if key.starts_with("g") {
            Scope::Global
        } else  {
            physical_scope.clone()
        };

        let mut found = false;
        if preferred_scope == Scope::Global {
            found = UserDefinitions::update_var_use(node, &mut self.global_defined_vars, &key, &access_type);
        } else {
            if let Some(local_map) = self.local_defined_vars.get_mut(&preferred_scope) {
                found = UserDefinitions::update_var_use(node, local_map, &key, &access_type);
            }
        }

        if !found && preferred_scope != Scope::Global && access_type != AccessVariableType::Write {
            found = UserDefinitions::update_var_use(node, &mut self.global_defined_vars, &key, &access_type);
        }

        if !found {
            let mut udv = UserDefinedVariable {
                node_location: node.start_byte(),
                var_name: key.clone(),
                var_scope: preferred_scope.clone(),
                var_calls: 1,
                is_undefined: false,
                is_unused: false,
                references: Vec::new()
            };

            if OMACROS.contains(&key.as_str()) {
                udv.var_scope = Scope::Global;
                udv.var_calls = 2;
                self.global_defined_vars.insert(key.clone(), udv);
            } else if pkind == "label_statement" {
                udv.var_scope = preferred_scope.clone();
                udv.is_unused = true;
                self.global_defined_vars.insert(key.clone(), udv);
            } else {
                let is_write = access_type == AccessVariableType::Write;
                udv.is_undefined = !is_write;
                udv.is_unused = is_write;

                if !is_write { udv.references.push(get_node_range(&node)); }

                if preferred_scope == Scope::Global {
                    self.global_defined_vars.insert(key.clone(), udv);
                } else {
                    self.local_defined_vars
                        .entry(preferred_scope)
                        .or_insert_with(HashMap::new)
                        .insert(key.clone(), udv);
                }
            }
        }
    }

    pub fn add_udt<'a>(&mut self, node: Node<'a>, key: &String, text: &String) {
        let mut cache: HashSet<String> = HashSet::new();
        let mut formats = Vec::new();
        let mut completion_items = Vec::new();
        let mut cursor = node.walk();
        let mut local_udt = UserDefinedType::new();
        for child in node.children_by_field_name("struct_field", &mut cursor) {
            let child_name = child.child_by_field_name("name").and_then(|n| get_node_name(n, &text));
            let child_type = child.child_by_field_name("type").and_then(|n| get_node_name(n, &text));


            if let (Some(nc), Some(tc)) = (child_name, child_type) {
                formats.push(format!("{}:{}", nc, tc));
                completion_items.push((nc, tc));
            }
        }

        let struct_format = format!("struct {} {}", key, formats.join(", "));
        if !formats.is_empty() {
            local_udt.udt_members = Some(completion_items);
        }

        if !self.user_defined_types.contains_key(&key.clone()) {
            local_udt.udt_name = key.clone();
            local_udt.udt_format = struct_format;
            self.user_defined_types.insert(key.clone(), local_udt);
        } else {
            if let Some (f) = self.user_defined_types.get_mut(key) {
                (*f).udt_format = struct_format;
            }
        }
    }

    pub fn add_udo<'a>(&mut self, node: Node<'a>, key: &String, text: &String) {
        let mut formats = Vec::new();
        let inputs_node = node.child_by_field_name("inputs");
        if let Some(inputs) = inputs_node {
            let inputs_text = get_node_name(inputs, &text).unwrap();
            formats.push(inputs_text);

            let outputs_node = node.child_by_field_name("outputs");
            if let Some(outputs) = outputs_node {
                let outputs_text = get_node_name(outputs, &text).unwrap();
                formats.push(outputs_text);
            }
            let opcode_format = match node.kind() {
                "udo_definition_legacy" => format!("opcode {} {}", key, formats.join(", ")),
                "udo_definition_modern" => format!("opcode {} {}", key, formats.join(":")),
                _ => { "No defition".to_string() }
            };
            if !self.user_defined_opcodes.contains_key(key) {
                self.user_defined_opcodes.insert(key.clone(), opcode_format);
            } else {
                if let Some (f) = self.user_defined_opcodes.get_mut(key) {
                    *f = opcode_format;
                }
            }
        }
    }
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
        let clean_name = name.trim_end_matches(":");
        return Some(clean_name.to_string())
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

    match node.kind() {
        "modern_udo_outputs" => {
            if trimmed.eq_ignore_ascii_case("void") {
                return true
            }
        },
        "udo_definition_legacy" => {
            if trimmed.contains('0') {
                if trimmed.len() == 1 {
                    return true
                } else {
                    return false
                }
            }
        },
        _ => { }
    }

    let mut chars = trimmed.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            'a' | 'f' | 'i' | 'j' | 'k' | 'K' | 'S'  => { },
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

pub fn iterate_tree<'a>(
    tree: &'a Tree,
    text: &String,
) -> NodeCollects<'a> {

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
                if let Some(p) = node.parent() {
                    if let Some(node_explicit_type) = node.child_by_field_name("type") {
                        let node_name = node.child_by_field_name("name").unwrap();
                        if node_explicit_type.kind() == "identifier" {
                            nodes_to_diagnostics.types.push(node_explicit_type);
                        }

                        let name = get_node_name(node_name, &text).unwrap();
                        let ty = get_node_name(node_explicit_type, &text).unwrap();
                        if let Some(n) = nodes_to_diagnostics.typed_vars.get_mut(&name) {
                            *n = ty
                        } else {
                            nodes_to_diagnostics.typed_vars.insert(name.clone(), ty);
                        }

                        let is_struct_field = node.parent().map(|p| p.kind() == "struct_definition").unwrap_or(false);
                        let is_opcode_name = node.parent().map(|p| p.kind() == "opcode_name").unwrap_or(false);
                        if !is_struct_field && !is_opcode_name {
                            nodes_to_diagnostics.user_definitions.add_udv(node, &name, text);
                        }
                    }
                }
            },
            "identifier" | "type_identifier_legacy" => {
                let parent = node.parent();
                let should_skip = parent.map(|p| {
                    let pk = p.kind();
                    pk == "ERROR"                       ||
                    pk == "typed_identifier"            ||
                    pk == "global_typed_identifier"     ||
                    pk == "struct_definition"           ||
                    pk == "macro_args"                  ||
                    pk == "flag_content"                ||
                    pk == "instrument_definition"       ||
                    (pk == "struct_access"    && p.child_by_field_name("struct_member").map(|m| m.id() == node.id()).unwrap_or(false))     ||
                    (pk == "opcode_statement" && p.child_by_field_name("op").map(|op| op.id() == node.id()).unwrap_or(false))       ||
                    (pk == "opcode_statement" && p.child_by_field_name("op_macro").map(|op| op.id() == node.id()).unwrap_or(false)) ||
                    (pk == "function_call"    && p.child_by_field_name("function").map(|f| f.id() == node.id()).unwrap_or(false))
                }).unwrap_or(false);

                if !should_skip {
                    if let Some(name) = get_node_name(node, text) {
                        if !vec!["CsScore", "CsoundSynthesizer", "CsoundSynthesiser", "CsOptions", "CsInstruments"].contains(&name.as_str()) {
                            let name = name.split("[").next().unwrap();
                            nodes_to_diagnostics.user_definitions.add_udv(node, &name.to_string(), text);
                        }
                    }
                }

                if let Some(p) = parent {
                    match p.kind() {
                        "ERROR" => {
                            let scope = find_scope(node, &text);
                            if scope == Scope::Score {
                                nodes_to_diagnostics.generic_errors.push(GenericError {
                                        node: node,
                                        error_type: GErrors::ScoreStatement
                                    }
                                );
                            }
                        },
                        _ => { }
                    }
                }
            },
            // check global vars
            "global_typed_identifier" => {
                if let Some(node_name) = node.child_by_field_name("name") {
                    if let Some(name) = get_node_name(node_name, text) {
                        nodes_to_diagnostics.user_definitions.add_udv(node_name, &name, text);
                    }
                }
            },
            // check macros
            "macro_define" => {
                if let Some(macro_name) = node.child_by_field_name("macro_name") {
                    if let Some(macro_name_text) = get_node_name(macro_name, &text) {
                        if let Some(macro_id) = macro_name.child_by_field_name("id") {
                            let mid = get_node_name(macro_id, &text).unwrap_or_default();
                            if let Some(values) = node.child_by_field_name("macro_values") {
                                let mv = get_node_name(values, &text).unwrap_or_default();

                                nodes_to_diagnostics.user_definitions.user_defined_macros
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
                            }
                        }
                    }
                }
            },
            // check user defined types
            "struct_definition" => {
                if let Some(node_type) = node.child_by_field_name("struct_name") {
                    if let Some(node_name) = get_node_name(node_type, &text) {
                        let node_key = node_name.clone();
                        nodes_to_diagnostics.udt.insert(node_name);
                        nodes_to_diagnostics.user_definitions.add_udt(node, &node_key, &text);
                    };
                }
            },
            "udo_definition_legacy" | "udo_definition_modern" => {
                if let Some(node_name) = node.child_by_field_name("name") {
                    if let Some(op_name) = get_node_name(node_name, &text) {
                        let node_key = op_name.clone();
                        nodes_to_diagnostics.user_definitions.add_udo(node, &node_key, &text);
                    }
                }
            },
            "legacy_udo_args" => {
                if let Some(text_content) = get_node_name(node, &text) {

                    let is_inputs_context = node.parent()
                        .and_then(|p| p.child_by_field_name("inputs"))
                        .map(|in_node| in_node.id() == node.id())
                        .unwrap_or(false);

                    let is_valid = if is_inputs_context {
                        is_valid_input_udo_types(&text_content)
                    } else {
                        let parent = node.parent();
                        if let Some(p) = parent {
                            is_valid_output_udo_types(&text_content, p)
                        } else {
                            false
                        }
                    };

                    if !is_valid {
                        nodes_to_diagnostics.generic_errors.push(GenericError {
                            node: node,
                            error_type: GErrors::ExplicitType,
                        });
                    }
                }
            },
            "score_statement_i" => {
                let pkind = node.parent().map(|p| p.kind()).unwrap();
                if pkind == "ERROR" {
                    nodes_to_diagnostics.generic_errors.push(GenericError {
                        node: node,
                        error_type: GErrors::MissingPfield
                    });
                }
            }
            // check ERROR node
            "ERROR" => {
                if let Some(node_name) = get_node_name(node, &text) {
                    let scope = find_scope(node, &text);
                    let trim_name = node_name.trim();
                    let current_parent_kind = node.parent()
                        .map(|p| p.kind())
                        .unwrap_or("");

                    let condition = {
                        !trim_name.contains(")") &&
                        !trim_name.contains(",") &&
                        !trim_name.contains("]") &&
                        !trim_name.contains("<")
                    };

                    if scope != Scope::Score && current_parent_kind != "modern_udo_outputs" && condition {
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

        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                to_visit.push(c);
            }
        }
    }

    for (_, lscope) in nodes_to_diagnostics.user_definitions.local_defined_vars.iter() {
        for (_, var) in lscope.iter() {
            if !var.references.is_empty() { nodes_to_diagnostics.user_definitions.undefined_vars.push(var.clone()); }
            if var.is_unused { nodes_to_diagnostics.user_definitions.unused_vars.push(var.clone()); }
        }
    }

    for (_, var) in nodes_to_diagnostics.user_definitions.global_defined_vars.iter() {
        if !var.references.is_empty() { nodes_to_diagnostics.user_definitions.undefined_vars.push(var.clone()); }
        if var.is_unused { nodes_to_diagnostics.user_definitions.unused_vars.push(var.clone()); }
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

pub fn find_node_at_cursor<'a>(tree: &'a Tree, pos: &Position, text: &str) -> Option<Node<'a>> {
    let target_line = pos.line as usize;
    let target_char = pos.character as usize;

    let line = text.lines().nth(target_line).unwrap_or("");

    let mut current_char_utf16 = 0 as usize;
    let mut current_char_utf8 = 0 as usize;
    for char in line.chars() {
        let char_utf16 = char.len_utf16();
        if current_char_utf16 + char_utf16 >= target_char {
            break;
        }
        current_char_utf16 += char_utf16;
        current_char_utf8 += char.len_utf8();
    }

    find_node_at_position(&tree, &Position { line: target_line as u32, character: current_char_utf8 as u32})

}

// find local scope
pub fn find_scope<'a>(node: Node<'a>, text: &String) -> Scope {
    let mut current_node = node;
    loop {
        let ckind = current_node.kind();
        if let Some(node_child) = current_node.child_by_field_name("name") {
            if let Some(n) = get_node_name(node_child, &text) {
                match ckind {
                    "instrument_definition" | "instr"  => return  Scope::Instr(n),
                    "udo_definition_modern" | "udo_definition_legacy" => return  Scope::Udo(n),
                    _ => { }
                }
            }
        }

        if ckind == "score_block" || ckind == "cs_score" {
            return Scope::Score
        }

        if let Some(p) = current_node.parent() {
            current_node = p;
        } else {
            return Scope::Global;
        }
    };
}

fn get_access_type(node: Node, text: &String) -> AccessVariableType {
    let mut current_node = node;
    for i in 0..6 {
        let parent = match current_node.parent() {
            Some(p) => p,
            None => return AccessVariableType::Read
        };

        let p_kind = parent.kind();

        if p_kind == "xin_statement"            || p_kind == "modern_udo_inputs"   ||
           p_kind == "for_loop"                 || p_kind == "score_nestable_loop" ||
           p_kind == "file_score_nestable_loop" || p_kind == "macro_name"
        { return AccessVariableType::Write; }

        if p_kind.contains("assignment_statement") {
            let mut cursor = current_node.walk();
            let childrens = parent.children_by_field_name("left", &mut cursor);
            for child in childrens {
                if node.start_byte() >= child.start_byte() && current_node.end_byte() <= child.end_byte() {
                    if let Some(op) = parent.child_by_field_name("operator") {
                        if let Some(op_text) = get_node_name(op, text) {
                            if ["+=", "-=", "*=", "/=", "%="].contains(&op_text.as_str()) {
                                return AccessVariableType::Update;
                            }
                        }
                    }
                    if child.kind() != "," {
                        return AccessVariableType::Write;
                    }
                }
            }
            return AccessVariableType::Read;
        }

        if p_kind == "opcode_statement" {
            if let Some(op_node) = parent.child_by_field_name("op").or_else(|| parent.child_by_field_name("op_macro")) {
                if current_node.end_byte() <= op_node.start_byte() {
                    return AccessVariableType::Write;
                }
                if current_node.start_byte() >= op_node.end_byte() {
                    return AccessVariableType::Read;
                }
            }
        }

        current_node = parent;
    }
    AccessVariableType::Read
}

fn expand_includes(content: &str) -> String {
    let rex = Regex::new(r#"--8<--\s+"([^"]+)""#).unwrap();
    rex.replace_all(content, |cap: &Captures| {
        let cap_str = &cap[1].to_string();
        let entire_path = Path::new(cap_str);
        let path = entire_path.file_name().and_then(|f| f.to_str()).unwrap();
        if let Some(c) = AssetCsoundOpcodeExamples::get(path) {
            match std::str::from_utf8(c.data.as_ref()) {
                Ok(f) => f.to_string(),
                Err(_) => format!("<!-- undefined includes {} -->", path)
            }
        } else {
            format!("<!-- undefined includes {} -->", path)
        }
    }).to_string()
}

pub fn load_opcodes() -> HashMap<String, String> {
    let mut map = HashMap::new();

    for file_path in AssetCsoundOpcodeReferences::iter() {
        let file_name = file_path.as_ref();
        if file_name.ends_with(".md") {
            let name = Path::new(file_name)
                .file_stem().and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();

            if let Some(content_file) = AssetCsoundOpcodeReferences::get(file_name) {
                if let Ok(content_str) = std::str::from_utf8(content_file.data.as_ref()) {
                    let content = expand_includes(&content_str);

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
    map
}

fn capture_to_token_type(capture: &str) -> Option<SemanticTokenType> {
    match capture {
        "attribute"                 => Some(SemanticTokenType::DECORATOR),
        "variable.parameter"        => Some(SemanticTokenType::PARAMETER),
        "macro.emphasis.strong"     => Some(SemanticTokenType::MACRO),
        "type"                      => Some(SemanticTokenType::TYPE),
        "comment"                   => Some(SemanticTokenType::COMMENT),
        "keyword" |
        "keyword.emphasis.strong"   => Some(SemanticTokenType::KEYWORD),
        "constant" |
        "constant.builtin" |
        "constant.builtin.emphasis" |
        "property"                  => Some(SemanticTokenType::PROPERTY),
        "tag" |
        "tag.emphsis"               => Some(SemanticTokenType::NAMESPACE),
        "variable" |
        "label"                     => Some(SemanticTokenType::VARIABLE),
        "string" |
        "string.special"            => Some(SemanticTokenType::STRING),
        "number"                    => Some(SemanticTokenType::NUMBER),
        "function" |
        "entity.name.function"      => Some(SemanticTokenType::FUNCTION),
        "operator"              |
        "punctuation.delimiter" |
        "punctuation.bracket"       => Some(SemanticTokenType::OPERATOR),
        _ => None,
    }
}

pub fn get_semantic_tokens(query: &Query, tree: &Tree, text: &String, offset: Option<Point>) -> Vec<(u32, u32, u32, u32, u32)> {
    let mut cursor = QueryCursor::new();
    let mut qmatches = cursor.matches(&query, tree.root_node(), text.as_bytes());
    let mut tokens: Vec<(u32, u32, u32, u32, u32)> = Vec::new(); // (line, col, length, type)

    while let Some(m) = qmatches.next() {
        for capture in m.captures {
            let capture_name = &query.capture_names()[capture.index as usize];
            if let Some(token_type) = capture_to_token_type(&capture_name) {
                let start_position = capture.node.start_position();

                let length = (capture.node.end_byte() - capture.node.start_byte()) as u32;
                let ttype = SEMANTIC_TOKENS.iter().position(|t| t == &token_type).unwrap() as u32;

                let mut line = start_position.row as u32;
                let mut col = start_position.column as u32;
                if let Some(off) = offset {
                    line += off.row as u32;
                    if start_position.row == 0 { col += off.column as u32; }
                }

                tokens.push((
                    line,
                    col,
                    length,
                    ttype,
                    0
                ));
            }
        }
    }
    tokens
}

pub fn get_delta_pos(semantic_tokens: &mut Vec<(u32, u32, u32, u32, u32)>) -> Vec<SemanticToken> {
    semantic_tokens.sort_by(|a, b| { if a.0 == b.0 { a.1.cmp(&b.1) } else { a.0.cmp(&b.0) }});
    let mut stokens = Vec::new();

    let mut prev_line = 0u32;
    let mut prev_start = 0u32;
    for (line, col, length, ttype, bitmask) in semantic_tokens {
        let delta_line = *line - prev_line;
        let delta_start = if delta_line == 0 {
            *col - prev_start
        } else {
            *col
        };

        stokens.push(SemanticToken {
            delta_line,
            delta_start,
            length: *length,
            token_type: *ttype,
            token_modifiers_bitset: *bitmask,
        });

        prev_line = *line;
        prev_start = *col;
    }
    stokens
}

pub fn get_injections(query_injection: &Query, tree: &Tree, text: &String, cs_parser: &mut Parser, cs_query: &Query, py_external: &mut ExternalQuery, html_external: &mut ExternalQuery)  -> Vec<(u32, u32, u32, u32, u32)> {
    let mut cursor = QueryCursor::new();
    let mut qmatches = cursor.matches(&query_injection, tree.root_node(), text.as_bytes());
    let index_content = query_injection.capture_index_for_name("injection.content").unwrap();

    let mut stokens = Vec::new();

    while let Some(m) = qmatches.next() {
        let settings = query_injection.property_settings(m.pattern_index);

        let mut lang = "";
        for p in settings {
            if &(*p.key) == "injection.language" {
                if let Some(val) = &p.value {
                    lang = val;
                }
            }
        }

        let capture_content = m.captures.iter().find(|c| c.index == index_content);
        if let Some(cap) = capture_content {
            let node = cap.node;
            let start_byte = node.start_byte();
            let end_byte = node.end_byte();
            let start_position = node.start_position();

            let block = &text[start_byte..end_byte].to_string();

            match lang {
                "python" => {
                    if let Some(py_tree) = py_external.parser.parse(&block, None) {
                        let py_tokens = get_semantic_tokens(&py_external.query, &py_tree, &block, Some(start_position));
                        stokens.extend(py_tokens);
                    }
                },
                "html" => {
                    if let Some(html_tree) = html_external.parser.parse(&block, None) {
                        let html_tokens = get_semantic_tokens(&html_external.query, &html_tree, &block, Some(start_position));
                        stokens.extend(html_tokens);
                    }
                },
                "csound" => {
                    if let Some(csound_tree) = cs_parser.parse(&block, None) {
                        let csound_tokens = get_semantic_tokens(&cs_query, &csound_tree, &block, Some(start_position));
                        stokens.extend(csound_tokens);
                    }
                },
                _ => { }
            }
        }

    }
    stokens
}

pub fn extract_manual(target_folder: &str) -> Result<(), std::io::Error>{
    let temp_path = Path::new(target_folder);

    for fpath in AssetCsoundManual::iter() {
        let content = AssetCsoundManual::get(fpath.as_ref()).unwrap();
        let dest = temp_path.join(fpath.as_ref());

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(&parent)?;
        }

        if !dest.exists() {
            std::fs::write(dest, content.data)?;
        }
    }

    Ok(())

}

pub fn make_indent(tree: &Tree, text: &String, line: usize) -> usize {
    let mut indent: usize = 0;
    let root = tree.root_node();

    let spoint = Point { row: line, column: 0 };
    let epoint = Point { row: line, column: 9999 };

    if let Some(node) = root.descendant_for_point_range(spoint, epoint) {
        let nkind = node.kind();
        let mut current = Some(node);
        while let Some(n) = current {
            if OPEN_BLOCKS.contains(&n.kind()) { indent += 1; }

            if (n.id() == node.id() || n.id() == node.parent().unwrap().id()) {
                if CLOSE_BLOCKS.contains(&nkind) { if indent > 0 { indent -= 1; } }
            }

            current = n.parent()
        }
    }
    indent
}
