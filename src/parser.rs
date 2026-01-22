#![allow(unused)]

use crate::utils::{ self, CLOSE_BLOCKS, OMACROS, OPEN_BLOCKS, OPENER, SEMANTIC_TOKENS };
use crate::resolve_udos::UdoFile;
use crate::assets;
use regex::{ Regex, Captures };
use ropey::Rope;

use rust_embed::{ EmbeddedFile, RustEmbed };
use tokio::process::Child;
use tower_lsp::lsp_types::{
    lsif::ItemKind,
    Position,
    Range,
    Diagnostic,
    SemanticTokenType,
    SemanticToken,
    SemanticTokensResult,
    SemanticTokens,
    SemanticTokensLegend,
    SemanticTokenModifier,
    Url
};

use std::io::Cursor;
use std::{
    fmt::{ self, Display, Formatter },
    path::{ Path, PathBuf },
    collections::{ HashMap, HashSet },
    fs
};

use tree_sitter::{
    Node,
    Parser,
    Point,
    Tree,
    Query,
    QueryCursor,
    StreamingIterator
};

use serde::Deserialize;
use tree_sitter_python;
use tree_sitter_html;
use tree_sitter_json;
use tree_sitter_csound::{ LANGUAGE, INJECTIONS_QUERY, HIGHLIGHTS_QUERY };
use once_cell::sync::Lazy;

static SHAPE_VAR_REGEX: Lazy<Regex>  = Lazy::new(|| Regex::new(r"\[\]").unwrap());
static TOKENIKE_VAR: Lazy<Regex>  = Lazy::new(|| Regex::new(r"[ijkapOKVJSbfw](?:\[\])*").unwrap());


pub fn get_token_lengend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: SEMANTIC_TOKENS.to_vec(),
        token_modifiers: vec![SemanticTokenModifier::DECLARATION]
    }
}

pub struct ParsedTree {
    pub tree: Tree,
    pub tree_type: TreeType
}

pub struct InternalParsers {
    pub csound_parser: Parser,
    pub py_parser: Parser,
    pub html_parser: Parser,
    pub json_parser: Parser,
}

pub struct Queries {
    pub csound_highlights: Query,
    pub csound_injection: Query,
    pub py_highlights: Query,
    pub html_highlights: Query,
    pub json_highlights: Query
}

pub fn load_queries() -> Queries {
    Queries {
        csound_highlights: Query::new(&LANGUAGE.into(), HIGHLIGHTS_QUERY).unwrap(),
        csound_injection: Query::new(&LANGUAGE.into(), INJECTIONS_QUERY).unwrap(),
        py_highlights: Query::new(&tree_sitter_python::LANGUAGE.into(), tree_sitter_python::HIGHLIGHTS_QUERY).unwrap(),
        html_highlights: Query::new(&tree_sitter_html::LANGUAGE.into(), tree_sitter_html::HIGHLIGHTS_QUERY).unwrap(),
        json_highlights: Query::new(&tree_sitter_json::LANGUAGE.into(), tree_sitter_json::HIGHLIGHTS_QUERY).unwrap(),
    }
}

pub fn load_parsers() -> InternalParsers {
    let mut p = Parser::new();
    let language = LANGUAGE.into();
    p.set_language(&language).unwrap();

    let mut py = Parser::new();
    let py_language = tree_sitter_python::LANGUAGE.into();
    py.set_language(&py_language).unwrap();

    let mut html = Parser::new();
    let html_language = tree_sitter_html::LANGUAGE.into();
    html.set_language(&html_language).unwrap();

    let mut json = Parser::new();
    let json_language = tree_sitter_json::LANGUAGE.into();
    json.set_language(&json_language).unwrap();

    InternalParsers {
        csound_parser: p,
        py_parser: py,
        html_parser: html,
        json_parser: json,
    }
}

pub fn parse_doc(text: &str, old_tree: Option<&Tree>) -> ParsedTree {
    let mut p = Parser::new();
    let language = LANGUAGE.into();
    p.set_language(&language).unwrap();

    let tree = p.parse(text, old_tree).unwrap();
    let tree_type = get_doc_type(tree.root_node());

    ParsedTree {
        tree,
        tree_type
    }
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
    MissingPfield,
    ControlLoopSyntaxError,
    InstrBlockSyntaxError,
    UdoBlockSyntaxError
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
    pub included_udo_files: HashMap<String, UdoFile>,
    pub flags: HashMap<String, Node<'a>>
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
            included_udo_files: HashMap::new(),
            flags: HashMap::new()
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
    Global,
    Unknown
}

#[derive(Debug, PartialEq)]
pub enum AccessVariableType {
    Read,
    Write,
    Update
}

#[derive(Debug, Clone)]
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
pub enum VarDataShape {
    Scalar,
    Array(u8),
    Boolean,
    Spectra,
    Expression,
    Struct(String),
    NoShape,
    Unknown
}

#[derive(Debug, Clone)]
pub enum VarDataType {
    InitTime,
    KontrolRate,
    AudioRate,
    String,
    Spectral,
    Macro,
    InstrDef,
    Instr,
    Opcode,
    OpcodeDef,
    Complex,
    Bool,
    Typedef(String),
    Void,
    Unknown
}

#[derive(Debug, Clone)]
pub struct VariableData {
    pub data_type: VarDataType,
    pub data_shape: VarDataShape
}

impl Display for VariableData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Type: {:?}, Shape: {:?}", self.data_type, self.data_shape)
    }
}

#[derive(Debug, Clone)]
pub enum UdoType {
    Legacy,
    Modern
}

#[derive(Debug, Clone)]
pub struct UdoArg {
    pub position: usize,
    pub arg: VariableData
}

#[derive(Debug, Clone)]
pub struct Udo {
    pub signature: String,
    pub inputs: Vec<UdoArg>,
    pub outputs: Vec<UdoArg>
}

impl Display for Udo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Udo: {}", self.signature)
    }
}

// must be is_valid udo args check first!
fn get_udo_data_type(arg_list: &String) -> Vec<VariableData> {
    let trimmed = arg_list.trim();

    if matches!(trimmed, "void" | "0") {
        return vec![VariableData { data_type: VarDataType::Void, data_shape: VarDataShape::NoShape }]
    }

    let tokens: Vec<&str> = TOKENIKE_VAR.find_iter(&trimmed).map(|c| c.as_str()).collect();

    let mut data = Vec::new();
    for t in tokens.iter() {
        let base_type = t.chars().find(|c| c.is_alphabetic()).unwrap();
        let dimension = t.matches("[]").count();

        let dtype = match base_type {
            'i' | 'j' |
            'o' | 'p'   => VarDataType::InitTime,
            'k' | 'O' |
            'P' | 'V' |
            'J' | 'K'   => VarDataType::KontrolRate,
            'a'         => VarDataType::AudioRate,
            'S'         => VarDataType::String,
            'b'         => VarDataType::Bool,
            'f' | 'w'   => VarDataType::Spectral,
            _           => VarDataType::Unknown
        };

        let shape = {
            if dimension != 0 {
                VarDataShape::Array(dimension as u8)
            } else {
                match dtype {
                    VarDataType::InitTime    |
                    VarDataType::KontrolRate |
                    VarDataType::AudioRate   |
                    VarDataType::String     => VarDataShape::Scalar,
                    VarDataType::Bool       => VarDataShape::Boolean,
                    VarDataType::Spectral   => VarDataShape::Spectra,
                    VarDataType::Void       => VarDataShape::NoShape,
                    _                       => VarDataShape::Unknown
                }
            }
        };
        data.push(VariableData { data_type: dtype, data_shape: shape });
    }

    data
}

// also use for modern udo inputs parse
fn get_variable_data_type(vnode: Node, text: &String, udt: &HashMap<String, UserDefinedType>) -> Option<VariableData> {
    let vnode_type = match vnode.kind() {
        "typed_identifier" | "global_typed_identifier" =>  vnode.child_by_field_name("type")?,
        "type_identifier_legacy" => vnode,
        _ => { return None }
    };

    let typed = get_node_name(vnode_type, &text)?;
    let absolute_trimmed = typed.trim();

    let legacy_flag = vnode.kind() == "type_identifier_legacy";
    let trimmed = if legacy_flag {
        let nog = absolute_trimmed.strip_prefix("g").unwrap_or(&absolute_trimmed);
        nog.chars().next().map(|c| &nog[..c.len_utf8()]).unwrap_or("")
    } else {
        absolute_trimmed
    };

    let mut is_struct = None;

    let var_type =  trimmed.split("[").next().unwrap_or(&trimmed);
    let dtype = match var_type {
        "i"          => VarDataType::InitTime,
        "k"         => VarDataType::KontrolRate,
        "a"         => VarDataType::AudioRate,
        "S"         => VarDataType::String,
        "b"         => VarDataType::Bool,
        "f" | "w"   => VarDataType::Spectral,
        "InstrDef"  => VarDataType::InstrDef,
        "Instr"     => VarDataType::Instr,
        "Opcode"    => VarDataType::Opcode,
        "OpcodeDef" => VarDataType::OpcodeDef,
        "Complex"   => VarDataType::Complex,
        _               => {
            if let Some(t) = udt.get(trimmed) {
                is_struct = Some(t);
                VarDataType::Typedef(trimmed.to_string())
            } else {
                VarDataType::Unknown
            }
        },
    };

    let shape = {
        let dimension = SHAPE_VAR_REGEX.find_iter(&absolute_trimmed).count();
        if dimension != 0 {
            VarDataShape::Array(dimension as u8)
        } else {
            match dtype {
                VarDataType::InitTime    |
                VarDataType::KontrolRate |
                VarDataType::AudioRate   |
                VarDataType::String     => VarDataShape::Scalar,
                VarDataType::Bool       => VarDataShape::Boolean,
                VarDataType::Spectral   => VarDataShape::Spectra,
                VarDataType::Void       => VarDataShape::NoShape,
                VarDataType::Unknown    => VarDataShape::Unknown,
                _                       => {
                    if let Some(struct_def) = is_struct {
                        if let Some(ref m) = struct_def.udt_members {
                            let mut members = Vec::new();
                            for member in m.iter() {
                                members.push(format!("{}:{}", member.0, member.1));
                            }
                            VarDataShape::Struct(members.join(", "))
                        } else {
                            VarDataShape::Struct("Unknown members".to_string())
                        }
                    } else {
                        VarDataShape::Expression
                    }
                }
            }
        }
    };
    Some(VariableData { data_type: dtype, data_shape: shape })
}

#[derive(Debug, Clone)]
pub struct UserDefinedVariable {
    pub node_location: usize,
    pub var_name: String,
    pub var_scope: Scope,
    pub var_calls: usize,
    pub is_undefined: bool,
    pub is_unused: bool,
    pub references: Vec<Range>,
    pub data_type: Option<VariableData>
}

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
    pub user_defined_opcodes: HashMap<String, Udo>,
    pub user_defined_macros: HashMap<String, UserDefinedMacro>,
    pub undefined_vars: Vec<UserDefinedVariable>,
    pub unused_vars: Vec<UserDefinedVariable>,
    pub local_defined_vars: HashMap<Scope, HashMap<String, UserDefinedVariable>>,
    pub global_defined_vars: HashMap<String, UserDefinedVariable>,
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
        let node_range = get_node_range(&node, None);
        if let Some(var) = map.get_mut(k) {
            var.var_calls += 1;
            let p = node.parent().unwrap();
            let pkind = p.kind();

            match acc {
                AccessVariableType::Read => {
                    var.is_unused = false;
                    if var.is_undefined { var.references.push(node_range); }
                },
                AccessVariableType::Write => {
                    if pkind == "label_statement" { var.references.clear(); }
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
                references: Vec::new(),
                data_type: None
            };

            if OMACROS.contains(&key.as_str()) {
                udv.var_scope = Scope::Global;
                udv.var_calls = 2;
                udv.data_type = Some(VariableData {
                    data_type: VarDataType::Macro,
                    data_shape: VarDataShape::Expression
                });

                self.global_defined_vars.insert(key.clone(), udv);

            } else {
                let is_write = access_type == AccessVariableType::Write;
                udv.is_undefined = !is_write;
                udv.is_unused = is_write;

                let node_to_check = if is_global_syntax { parent.unwrap_or(node) } else { node };
                udv.data_type = get_variable_data_type(node_to_check, &text, &self.user_defined_types);

                if !is_write { udv.references.push(get_node_range(&node, None)); }

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

            let (opcode_format, inputs, outputs) = match node.kind() {
                "udo_definition_legacy" => {
                    let form = format!("opcode {} {}", key, formats.join(", "));
                    let inps = get_udo_data_type(&formats[1]);
                    let outs = get_udo_data_type(&formats[0]);
                    (form, inps, outs)
                },
                "udo_definition_modern" => {
                    let form = format!("opcode {} {}", key, formats.join(":"));
                    let inp_text: String = formats[0].chars().filter(|c| !matches!(*c, '(' | ')')).collect();
                    let inp_text = inp_text
                        .split(',')
                        .filter_map(|i| i.split(':').last())
                        .map(|s| s.trim().to_string())
                        .collect::<Vec<String>>()
                        .join("");
                    let out_text = formats[1].chars().filter(|c| !matches!(*c, '(' | ')')).collect();

                    let inps = get_udo_data_type(&inp_text);
                    let outs = get_udo_data_type(&out_text);
                    (form, inps, outs)
                },
                _ => { ("No defition".to_string(), vec![], vec![]) }
            };

            let arg_inputs: Vec<UdoArg> = inputs.iter().enumerate().map(|(p, v)| UdoArg { position: p, arg: v.clone()}).collect();
            let arg_outputs: Vec<UdoArg> = outputs.iter().enumerate().map(|(p, v)| UdoArg { position: p, arg: v.clone()}).collect();

            let udo = Udo { signature: opcode_format, inputs: arg_inputs, outputs: arg_outputs };
            if !self.user_defined_opcodes.contains_key(key) {
                self.user_defined_opcodes.insert(key.clone(), udo);
            } else {
                if let Some (f) = self.user_defined_opcodes.get_mut(key) {
                    *f = udo;
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
        "InstrDef" | "Instr" | "Opcode" | "OpcodeDef" | "Complex" => true,
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
    uri: &Url
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
                            let nkind = node.kind();
                            if scope == Scope::Score && nkind != "type_identifier_legacy" {
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
            "score_nestable_loop" | "score_statement" => {
                 if let Some(macro_name) = node.child_by_field_name("macro_identifier") {
                    if let Some(macro_name_text) = get_node_name(macro_name, &text) {
                        let mname = macro_name_text.trim().to_string();
                        nodes_to_diagnostics.user_definitions.user_defined_macros
                            .entry(mname.clone())
                            .and_modify(|m| {
                                m.node_location = macro_name.start_byte();
                                m.macro_label = mname.clone();
                                m.macro_values = "Score statement macro".to_string()
                            })
                            .or_insert_with(|| UserDefinedMacro {
                                node_location: macro_name.start_byte(),
                                macro_name: mname.clone(),
                                macro_label: mname.clone(),
                                macro_values: "Score statement macro".to_string()
                            });
                    }
                 }
            }
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
            "score_statement_func" => {
                let node_mode = node.child(0);

                let name = node_mode.map(|c| {
                    c.child_by_field_name("id").and_then(|n| get_node_name(n, &text))
                }).unwrap_or(None);

                let is_valid_instr = name
                    .as_deref()
                    .and_then(|n| Some(n.trim()
                        .strip_prefix("i")
                        .is_some() && node.child_count() >= 3));

                match is_valid_instr {
                    Some(condition) => {
                        if !condition {
                                nodes_to_diagnostics.generic_errors.push(GenericError {
                                node: node,
                                error_type: GErrors::MissingPfield
                            });
                        }
                    },
                    None => { }
                }
            },
            "score_statement_instr" => {
                let p1 = node.field_name_for_child(0);
                if let Some(c) = p1 {
                    let mode = (c == "statement") as u32;
                    let is_valid_instr = {
                        let p1 = node.field_name_for_child(0 + mode);
                        let p2 = node.field_name_for_child(1 + mode);
                        let p3 = node.field_name_for_child(2 + mode);
                        let ans = if !p1.is_some() || !p2.is_some() || !p3.is_some() {
                            false
                        } else {
                            let p1 = p1.unwrap_or("");
                            let p2 = p2.unwrap_or("");
                            let p3 = p3.unwrap_or("");
                            if !matches!(p1, "instr" | "statement_instr" | "statement_macro_instr") || p2 != "start_time" || p3 != "duration" {
                                false
                            } else {
                                true
                            }
                        };
                        ans
                    };
                    if !is_valid_instr {
                        nodes_to_diagnostics.generic_errors.push(GenericError {
                            node: node,
                            error_type: GErrors::MissingPfield
                        });
                    }
                }
            },
            "include_directive" => {
                if let Some(c) = node.child_by_field_name("included_file") {
                    if let Some(ifile) = get_node_name(c, &text) {
                        let fpath = ifile.replace("\"", "");
                        let pfile = Path::new(fpath.trim());
                        if pfile.extension().and_then(|e| e.to_str()) == Some("udo") {
                            let uf = UdoFile::new(&pfile, uri.clone());
                            nodes_to_diagnostics.included_udo_files
                                .entry(pfile.to_string_lossy().to_string())
                                .and_modify(|m| {
                                    if m.content_hash != uf.content_hash {
                                        m.content_hash = uf.content_hash.clone();
                                        m.content = uf.content.clone()
                                    }
                                })
                                .or_insert(uf);
                        }
                    }
                }
            },
            "control_statement" => {
                let mut c = node.walk();
                let control_kind = node
                    .children(&mut c)
                    .find_map(|n| {
                        let close = match n.kind() {
                            "if_statement" => vec!["kw_endif", "kw_fi", "then_goto"],
                            "while_loop" | "for_loop" | "until_loop" => vec!["kw_od", "od"],
                            "switch_statement" => vec!["kw_switch_end", "endsw"],
                            _ => return None
                        };
                        Some((n, close))
                    });

                if let Some((cnode, expected)) = control_kind {
                    if has_specific_node(cnode, "control_statement_bounded_error") {
                        nodes_to_diagnostics.generic_errors.push(GenericError {
                                node: node,
                                error_type: GErrors::ControlLoopSyntaxError
                            }
                        );
                    } else {
                        let is_closed = expected
                            .iter()
                            .map(|closer| {
                                if *closer == "then_goto" {
                                    cnode.child_by_field_name("then_goto").is_some()
                                } else {
                                    has_specific_node(cnode, closer)
                                }
                            })
                            .any(|c| c == true);

                        if !is_closed {
                            nodes_to_diagnostics.generic_errors.push(GenericError {
                                    node: node,
                                    error_type: GErrors::ControlLoopSyntaxError
                                }
                            );
                        }
                    }
                }
            },
            "instrument_definition" | "udo_definition" => {
                let first_child = node.child(0);
                if let Some(n) = first_child {
                    match n.kind() {
                        "instr" => {
                            if has_specific_node(node, "instr_udo_bounded_error") {
                                nodes_to_diagnostics.generic_errors.push(GenericError {
                                        node: node,
                                        error_type: GErrors::InstrBlockSyntaxError
                                    }
                                );
                            }
                        },
                        "udo_definition_legacy" | "udo_definition_modern" => {
                            if has_specific_node(node, "instr_udo_bounded_error") {
                                nodes_to_diagnostics.generic_errors.push(GenericError {
                                        node: node,
                                        error_type: GErrors::UdoBlockSyntaxError
                                    }
                                );
                            }
                        },
                        _ => { }
                    }
                }
            },
            "options_block" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "flag_content" {
                        if let (Some(fi), Some(ft)) = {
                            let mut child_cursor = child.walk();
                            (
                                child.children(&mut child_cursor).find(|n| n.kind() == "flag_identifier"),
                                child.child_by_field_name("flag_type")
                            )
                        } {
                            let flag = format!(
                                "{}{}",
                                get_node_name(fi, &text).unwrap_or_default(),
                                get_node_name(ft, &text).unwrap_or_default()
                            );
                            nodes_to_diagnostics.flags.insert(flag.trim().to_string(), child);
                        }
                    }
                }
            }
            // check ERROR node
            "ERROR" => {
                if let Some(node_name) = get_node_name(node, &text) {
                    let trim_name = node_name.trim();
                    let condition = {
                        (!trim_name.contains("<CsInstruments>") && !trim_name.contains("</CsInstruments>")) ||
                        (!trim_name.contains("<CsScore>") && !trim_name.contains("</CsScore>")) ||
                        (!trim_name.contains("csd_file") && !trim_name.contains("cs_legacy_file"))
                    };
                    if condition {
                        let scope = find_scope(node, &text);
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
                                if scope == Scope::Score {
                                    nodes_to_diagnostics.generic_errors.push(GenericError {
                                            node: node,
                                            error_type: GErrors::ScoreStatement
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

pub fn get_node_range(node: &Node, expand_line: Option<&String>) -> Range {
    let mut start = node.start_position();
    let mut end = node.end_position();

    if let Some(text) = expand_line {
        end.row = start.row;
        end.column = text
            .lines()
            .nth(start.row)
            .map(|l| l.len())
            .unwrap_or(start.column);

        start.column = 0;
    }

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
    let current_char_utf8 = utils::find_char_byte(line, target_char);
    find_node_at_position(&tree, &Position { line: target_line as u32, character: current_char_utf8 as u32 })
}

// find local scope
pub fn find_scope<'a>(node: Node<'a>, text: &String) -> Scope {
    let mut current_node = node;
    if current_node.kind() == "ERROR" { return Scope::Unknown }
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
            let pflag = node.parent().map(|p| p.kind() == "macro_name").unwrap_or(false);
            if pflag { return Scope::Global } else { return Scope::Score }
        }

        if ckind == "instrument_block" || ckind == "cs_legacy_file" {
            return Scope::Global
        }

        if let Some(p) = current_node.parent() {
            current_node = p;
        } else {
            break;
        }
    };
    Scope::Global
}

fn get_access_type(node: Node, text: &String) -> AccessVariableType {
    let mut current_node = node;
    for i in 0..12 {
        let parent = match current_node.parent() {
            Some(p) => p,
            None => return AccessVariableType::Read
        };

        let p_kind = parent.kind();

        if node.kind() == "identifier" {
            if p_kind == "macro_usage" { return AccessVariableType::Read; }

            if p_kind == "score_nestable_loop"     || p_kind == "score_statement"       ||
               p_kind == "score_statement_instr"   || p_kind == "score_statement_func"  ||
               p_kind == "score_statement_wm"
            { return AccessVariableType::Write; }
        }

        if p_kind == "xin_statement"            || p_kind == "modern_udo_inputs"   ||
           p_kind == "for_loop"                 || p_kind == "macro_define"
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

        if p_kind == "label_statement" {
            if let Some(op_node) = parent.child_by_field_name("label_name") {
                for i in 0..parent.child_count() {
                    let c = parent.child(i).unwrap();
                    if c.kind() == ":" {
                        return AccessVariableType::Read
                    }
                }
                return AccessVariableType::Write
            }
        }

        current_node = parent;
    }
    AccessVariableType::Read
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
                let end_position = capture.node.end_position();

                let length = (capture.node.end_byte() - capture.node.start_byte()) as u32;
                let ttype = SEMANTIC_TOKENS.iter().position(|t| t == &token_type).unwrap() as u32;

                if start_position.row == end_position.row {
                    let mut line = start_position.row as u32;
                    let mut col = start_position.column as u32;
                    if let Some(off) = offset {
                        line += off.row as u32;
                        if start_position.row == 0 { col += off.column as u32; }
                    }

                    tokens.push((line, col, length, ttype, 0));
                } else {
                    let start_byte = capture.node.start_byte();
                    let end_byte = capture.node.end_byte();
                    let ntext = &text[start_byte..end_byte];

                    for (i, line_content) in ntext.lines().enumerate() {
                        let current_row = start_position.row + i;
                        let current_column = if i == 0 { start_position.column } else { 0 };
                        let lenght = line_content.encode_utf16().count();
                        if lenght == 0 { continue; }

                        let mut final_row = current_row as u32;
                        let mut final_column = current_column as u32;

                        if let Some(off) = offset {
                            final_row += off.row as u32;
                            if start_position.row == 0 { final_column += off.column as u32; }
                        }

                        tokens.push((final_row, final_column, length, ttype, 0));
                    }
                }
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

pub fn get_injections(
    query_injection: &Query,
    tree: &Tree,
    text: &String,
    cs_parser: &mut Parser,
    cs_query: &Query,
    py_parser: &mut Parser,
    py_query: &Query,
    html_parser: &mut Parser,
    html_query: &Query,
    json_parser: &mut Parser,
    json_query: &Query
) -> Vec<(u32, u32, u32, u32, u32)>
{
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
                    if let Some(py_tree) = py_parser.parse(&block, None) {
                        let py_tokens = get_semantic_tokens(&py_query, &py_tree, &block, Some(start_position));
                        stokens.extend(py_tokens);
                    }
                },
                "html" => {
                    if let Some(html_tree) = html_parser.parse(&block, None) {
                        let html_tokens = get_semantic_tokens(&html_query, &html_tree, &block, Some(start_position));
                        stokens.extend(html_tokens);
                    }
                },
                "json" => {
                    if let Some(json_tree) = json_parser.parse(&block, None) {
                        let json_tokens = get_semantic_tokens(&json_query, &json_tree, &block, Some(start_position));
                        stokens.extend(json_tokens);
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

fn find_first_node_down_in_list<'a>(node: &Node<'a>, names: &[&'static str]) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|c| {
            let ck = c.kind();
            names.contains(&ck)
        })
}

pub fn make_indent(tree: &Tree, text: &String, line: usize) -> usize {
    let mut indent: i32 = 0;
    let root = tree.root_node();

    let line_text = text.lines().nth(line).unwrap_or("");
    let first_non_whitespace = line_text.chars().take_while(|c| c.is_whitespace()).count();

    let spoint = Point { row: line, column: first_non_whitespace };
    // let epoint = Point { row: line, column: 9999 };

    if let Some(node) = root.descendant_for_point_range(spoint, spoint) {
        let mut current = Some(node);
        let mut  depth = 0;
        while let Some(n) = current {
            if depth > 128 {
                break;
            }

            let nkind = n.kind();
            let start_row = n.start_position().row;

            if nkind == "raw_script" {
                let start_line_text = text.lines().nth(start_row).unwrap_or("");
                let base_indent = start_line_text.chars().take_while(|c| c.is_whitespace()).count() as i32;
                indent = base_indent;
                for i in start_row..line {
                    if let Some(l) = text.lines().nth(i) {
                        let clean_line = l.split("//").next().unwrap().split(';').next().unwrap().trim_end();

                        for c in clean_line.chars() {
                            match c {
                                '{' | '[' | '(' => indent += 1,
                                '}' | ']' | ')' => indent -= 1,
                                _ => {}
                            }
                        }
                        if clean_line.ends_with(':') {
                            indent += 1;
                        }
                    }
                }

                let current_trimmed = line_text.trim();
                if current_trimmed.starts_with('}') || current_trimmed.starts_with(']') || current_trimmed.starts_with(')') {
                    indent -= 1;
                }
                if indent < 0 { return 0 } else { return indent as usize };
            }


            if OPEN_BLOCKS.iter().any(|k| *k == n.kind()) {
                if start_row < line { indent += 1; }
            }

            if nkind == "ERROR" {
                if let Some(_) = find_first_node_down_in_list(&n, &OPENER) {
                    indent += 1;
                }
            }

            if CLOSE_BLOCKS.iter().any(|k| *k == n.kind()) {
                if indent > 0 { indent -= 1; }
            }

            let is_middle = nkind == "kw_elseif" || nkind == "kw_else";
            if is_middle && start_row == line {
                indent -= 1;
            }

            current = n.parent();
            depth += 1;

        }
    }
    if indent < 0 { return 0 } else { return indent as usize };
}

pub fn add_local_udos_to_cs_references(udos: &HashMap<String, Udo>, cs_references: &mut assets::CsoundJsonData) -> bool {
    let opdata = cs_references.opcodes_data.as_mut();
    if let Some(opdata) = opdata {
        for (udo, prefix) in udos.iter() {
            let prefix = prefix.signature.clone();
            if let None = opdata.get(udo) {
                opdata.insert(udo.clone(), assets::OpcodesData {
                    prefix: prefix.strip_prefix("opcode ").unwrap().to_string(),
                    body: assets::BodyOpCompletion::SingleLine(udo.clone()),
                    description: format!("user-defined opcode" )
                });
            }
        }
        return true;
    }
    return false;
}

fn has_specific_node(node: Node, expected_kind: &str) -> bool {
    let mut cursor = node.walk();
    let mut skip_root = false;
    loop {
        let n = cursor.node();
        if skip_root {
            if n.kind() == "ERROR" { return false; }
            if n.kind() == expected_kind {
                if !n.is_missing() { return true; }
            }
        }

        if cursor.goto_first_child() {
            skip_root = true;
            continue;
        }

        if cursor.goto_next_sibling() { continue; }

        let mut block = false;
        while cursor.goto_parent() {
            if cursor.goto_next_sibling() {
                block = true;
                break;
            }
        }
        if !block { break; }
    }
    false
}

#[derive(PartialEq)]
pub enum TreeType {
    Csd,
    Sco,
    Orc,
    Unknown
}

pub fn get_doc_type(root_node: Node) -> TreeType {
    let mut cursor = root_node.walk();
    loop {
        let n = cursor.node();
        match n.kind() {
            "csd_file" =>  return TreeType::Csd,
            "cs_orchestra_udo" => return TreeType::Orc,
            "cs_score" => return TreeType::Sco,
            _ => { }
        }

        if cursor.goto_first_child() { continue; }
        if cursor.goto_next_sibling() { continue; }

        let mut block = false;
        while cursor.goto_parent() {
            if cursor.goto_next_sibling() {
                block = true;
                break;
            }
        }
        if !block { break; }
    }
    TreeType::Unknown
}
