use crate::assets::CsoundJsonData;
use crate::parser::{ self, Scope, TreeType, UserDefinedVariable, UserDefinitions, VarDataShape, VarDataType, VariableData };
use crate::resolve_udos::UdoFile;

use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    collections::{ HashMap, HashSet },
    path::Path
};
use tower_lsp::lsp_types::{
    CompletionContext,
    CompletionItem,
    CompletionItemKind,
    CompletionTextEdit,
    CompletionTriggerKind,
    Documentation,
    InsertTextFormat,
    Position,
    Range,
    TextEdit,
    Url
};
use tree_sitter::Tree;

static SECTION_TAG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"<(/?)(CsOptions|CsInstruments|CsScore|CsoundSynthesi[sz]er|CabbageARA|Cabbage|CsFileB|CsFile|CsMidifileB|CsSampleB|CsLicen[cs]e|CsShortLicen[cs]e|html)([^>]*)>").unwrap()
});
static BLOCK_BOUNDARY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^[ \t]*(instr|opcode|endin|endop)\b[ \t]*([^\s,;(]*)").unwrap());
static DEFINITION_LINE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(instr|opcode)\b").unwrap());
static STRUCT_CHAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Za-z_]\w*(?:\[[^\]]*\])*(?:\.[A-Za-z_]\w*(?:\[[^\]]*\])*)*)\.$").unwrap()
});
static SNIPPET_PLACEHOLDER: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{?\d").unwrap());

const BASE_TYPES: [&str; 12] = [
    "a", "i", "k", "b", "S", "f", "w", "InstrDef", "Instr", "Opcode", "OpcodeDef", "Complex"
];

// keywords that have no entry in the opcode reference
const KEYWORDS: [&str; 12] = [
    "then", "ithen", "kthen", "fi", "do", "od", "case", "default", "endsw", "void", "true", "false"
];

#[derive(Debug, PartialEq)]
pub enum Region {
    Options,
    Orchestra,
    Score,
    Other
}

pub struct CompletionSources<'a> {
    pub text: &'a String,
    pub tree: &'a Tree,
    pub uri: &'a Url,
    pub doc_type: &'a TreeType,
    pub user_definitions: &'a UserDefinitions,
    pub typed_vars: &'a HashMap<String, String>,
    pub included_udo_files: &'a HashMap<String, UdoFile>,
    pub references: &'a CsoundJsonData
}

pub struct CursorContext<'a> {
    pub offset: usize,             // byte offset of the cursor in the document
    pub line_before: &'a str,      // current line up to the cursor
    pub prefix: &'a str,           // identifier characters right before the cursor
    pub before_prefix: &'a str     // current line up to the prefix
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn utf16_to_byte(line: &str, character: usize) -> usize {
    let mut units = 0;
    for (index, c) in line.char_indices() {
        if units >= character {
            return index;
        }
        units += c.len_utf16();
    }
    line.len()
}

fn utf16_len(s: &str) -> u32 {
    s.encode_utf16().count() as u32
}

fn matches_prefix(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn decode_entities(s: &str) -> String {
    s.replace("&ldquo;", "\u{201c}")
        .replace("&rdquo;", "\u{201d}")
        .replace("&lsquo;", "\u{2018}")
        .replace("&rsquo;", "\u{2019}")
        .replace("&commat;", "@")
        .replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub fn cursor_context<'a>(text: &'a str, pos: &Position) -> Option<CursorContext<'a>> {
    let line_start = if pos.line == 0 {
        0
    } else {
        text.match_indices('\n').nth(pos.line as usize - 1)?.0 + 1
    };
    let line_end = text[line_start..].find('\n').map(|i| line_start + i).unwrap_or(text.len());
    let line = text[line_start..line_end].trim_end_matches('\r');
    let column = utf16_to_byte(line, pos.character as usize);
    let line_before = &line[..column];
    let prefix_len: usize = line_before.chars().rev().take_while(|c| is_word_char(*c)).count();
    let split = line_before.len() - prefix_len; // word chars are ASCII

    Some(CursorContext {
        offset: line_start + column,
        line_before,
        prefix: &line_before[split..],
        before_prefix: &line_before[..split]
    })
}

pub fn region_at(text: &str, offset: usize, uri: &Url, doc_type: &TreeType) -> Region {
    let extension = Path::new(uri.path())
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    match extension.as_deref() {
        Some("sco") => return Region::Score,
        Some("orc") | Some("udo") | Some("inc") => return Region::Orchestra,
        Some("csd") => { },
        _ => match doc_type {
            TreeType::Sco => return Region::Score,
            TreeType::Orc => return Region::Orchestra,
            _ => if !SECTION_TAG.is_match(text) { return Region::Orchestra }
        }
    }

    let mut region = Region::Other;
    for cap in SECTION_TAG.captures_iter(&text[..offset]) {
        region = if &cap[1] == "/" {
            Region::Other
        } else {
            match &cap[2] {
                "CsOptions" => Region::Options,
                "CsInstruments" => Region::Orchestra,
                "CsScore" if !cap[3].contains("bin") => Region::Score,
                _ => Region::Other
            }
        };
    }
    region
}

fn in_comment_or_string(line_before: &str) -> bool {
    let mut in_string = false;
    let mut chars = line_before.chars().peekable();
    while let Some(c) = chars.next() {
        if in_string {
            match c {
                '\\' => { chars.next(); },
                '"' => in_string = false,
                _ => { }
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            ';' => return true,
            '/' if chars.peek() == Some(&'/') => return true,
            _ => { }
        }
    }
    in_string
}

fn in_block_comment(tree: &Tree, offset: usize) -> bool {
    if offset == 0 {
        return false;
    }
    tree.root_node()
        .descendant_for_byte_range(offset - 1, offset)
        .is_some_and(|n| n.kind() == "block_comment" && n.start_byte() < offset && offset < n.end_byte())
}

fn text_scope_at(text: &str, offset: usize) -> Option<Scope> {
    let mut scope = None;
    for cap in BLOCK_BOUNDARY.captures_iter(&text[..offset]) {
        scope = match &cap[1] {
            "instr" => Some(Scope::Instr(cap[2].to_string())),
            "opcode" => Some(Scope::Udo(cap[2].to_string())),
            _ => None
        };
    }
    scope
}

fn scope_at(src: &CompletionSources, offset: usize) -> Scope {
    let probe = offset.saturating_sub(1);
    let mut node = src.tree.root_node().named_descendant_for_byte_range(probe, probe);
    // find_scope gives up on ERROR nodes: start from the first valid ancestor
    while let Some(n) = node {
        if n.kind() != "ERROR" { break; }
        node = n.parent();
    }

    let scope = node
        .map(|n| parser::find_scope(n, src.text, &src.user_definitions.user_defined_types))
        .unwrap_or(Scope::Global);

    match scope {
        Scope::Instr(_) | Scope::Udo(_) | Scope::Score => scope,
        // the tree may not see the enclosing block while the code is being written
        _ => text_scope_at(src.text, offset).unwrap_or(scope)
    }
}

fn type_label(data: &VariableData) -> String {
    let base = match &data.data_type {
        VarDataType::InitTime => "i",
        VarDataType::KontrolRate => "k",
        VarDataType::AudioRate => "a",
        VarDataType::String => "S",
        VarDataType::Spectral => "f",
        VarDataType::Bool => "b",
        VarDataType::InstrDef => "InstrDef",
        VarDataType::Instr => "Instr",
        VarDataType::Opcode => "Opcode",
        VarDataType::OpcodeDef => "OpcodeDef",
        VarDataType::Complex => "Complex",
        VarDataType::Typedef(t) => t.as_str(),
        VarDataType::Macro | VarDataType::Void | VarDataType::Unknown => ""
    };
    match data.data_shape {
        VarDataShape::Array(dims) => format!("{}{}", base, "[]".repeat(dims as usize)),
        _ => base.to_string()
    }
}

fn variable_items(src: &CompletionSources, scope: &Scope, ctx: &CursorContext, items: &mut Vec<CompletionItem>) {
    let typed_start = ctx.offset - ctx.prefix.len();

    let mut push = |var: &UserDefinedVariable, documentation: &str| {
        let is_macro = var.data_type.as_ref().is_some_and(|d| d.data_type == VarDataType::Macro);
        if var.is_undefined || is_macro || !matches_prefix(&var.var_name, ctx.prefix) {
            return;
        }
        let detail = var.data_type.as_ref().map(type_label).filter(|t| !t.is_empty());
        items.push(CompletionItem {
            label: var.var_name.clone(),
            kind: Some(CompletionItemKind::VARIABLE),
            detail,
            documentation: Some(Documentation::String(documentation.to_string())),
            sort_text: Some(format!("0{}", var.var_name)),
            ..Default::default()
        });
    };

    if let Some(locals) = src.user_definitions.local_defined_vars.get(scope) {
        for var in locals.values() {
            // a local variable is offered only after its first definition
            if var.definition_location.is_some_and(|d| d < typed_start) {
                push(var, "Local variable");
            }
        }
    }

    for var in src.user_definitions.global_defined_vars.values() {
        // a global may be defined anywhere, but not by the word being typed
        if var.definition_location.is_some_and(|d| d != typed_start) {
            push(var, "Global variable");
        }
    }
}

fn udo_items(src: &CompletionSources, prefix: &str, items: &mut Vec<CompletionItem>, seen: &mut HashSet<String>) {
    let local = src.user_definitions.user_defined_opcodes
        .iter()
        .map(|(name, udo)| (name, udo, "User-defined opcode".to_string()));

    let included = src.included_udo_files.values().flat_map(|file| {
        let source = file.path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        file.user_defined_opcodes
            .iter()
            .map(move |(name, udo)| (name, udo, format!("User-defined opcode from {}", source)))
    });

    for (name, udo, documentation) in local.chain(included) {
        if !matches_prefix(name, prefix) || !seen.insert(name.clone()) {
            continue;
        }
        items.push(CompletionItem {
            label: name.clone(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some(udo.signature.clone()),
            documentation: Some(Documentation::String(documentation)),
            sort_text: Some(format!("1{}", name)),
            ..Default::default()
        });
    }
}

fn opcode_items(src: &CompletionSources, prefix: &str, items: &mut Vec<CompletionItem>, seen: &mut HashSet<String>) {
    let Some(opcodes) = src.references.opcodes_data.as_ref() else { return };

    for (name, data) in opcodes {
        let is_valid_name = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
        if !is_valid_name || !matches_prefix(name, prefix) || seen.contains(name) {
            continue;
        }
        let body = data.get_string_from_body();
        let is_snippet = SNIPPET_PLACEHOLDER.is_match(&body);
        items.push(CompletionItem {
            label: name.clone(),
            kind: Some(if is_snippet { CompletionItemKind::SNIPPET } else { CompletionItemKind::FUNCTION }),
            detail: Some(data.prefix.clone()),
            documentation: Some(Documentation::String(data.description.clone())),
            insert_text: Some(body),
            insert_text_format: Some(if is_snippet { InsertTextFormat::SNIPPET } else { InsertTextFormat::PLAIN_TEXT }),
            sort_text: Some(format!("2{}", name)),
            ..Default::default()
        });
    }
}

fn keyword_items(prefix: &str, items: &mut Vec<CompletionItem>) {
    for keyword in KEYWORDS.iter().filter(|k| matches_prefix(k, prefix)) {
        items.push(CompletionItem {
            label: keyword.to_string(),
            kind: Some(CompletionItemKind::KEYWORD),
            sort_text: Some(format!("3{}", keyword)),
            ..Default::default()
        });
    }
}

fn type_items(src: &CompletionSources, prefix: &str) -> Vec<CompletionItem> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();

    let base = BASE_TYPES.iter().map(|t| (t.to_string(), CompletionItemKind::TYPE_PARAMETER, "Data type".to_string()));
    let local = src.user_definitions.user_defined_types
        .values()
        .map(|t| (t.udt_name.clone(), CompletionItemKind::STRUCT, t.udt_format.clone()));
    let included = src.included_udo_files.values().flat_map(|file| {
        let source = file.path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        file.type_list
            .iter()
            .map(move |t| (t.clone(), CompletionItemKind::STRUCT, format!("User-defined type from {}", source)))
    });

    for (name, kind, documentation) in base.chain(local).chain(included) {
        if !matches_prefix(&name, prefix) || !seen.insert(name.clone()) {
            continue;
        }
        items.push(CompletionItem {
            label: name,
            kind: Some(kind),
            documentation: Some(Documentation::String(documentation)),
            ..Default::default()
        });
    }
    items
}

// `name:` is a type annotation, unlike `a ? b : c` or an array slice `arr[1:`
fn is_type_annotation(before_prefix: &str) -> bool {
    let Some(head) = before_prefix.strip_suffix(':') else { return false };
    let follows_name = head.chars().last().is_some_and(|c| is_word_char(c) || c == ')' || c == ']');
    let open_brackets = head.matches('[').count() > head.matches(']').count();
    follows_name && !open_brackets && !head.contains('?')
}

fn variable_type(src: &CompletionSources, scope: &Scope, name: &str) -> Option<String> {
    let var = src.user_definitions.local_defined_vars
        .get(scope)
        .and_then(|vars| vars.get(name))
        .or_else(|| src.user_definitions.global_defined_vars.get(name));

    if let Some(VarDataType::Typedef(t)) = var.and_then(|v| v.data_type.as_ref()).map(|d| &d.data_type) {
        return Some(t.clone());
    }
    src.typed_vars.get(name).cloned()
}

fn struct_members(src: &CompletionSources, type_name: &str) -> Option<Vec<(String, String)>> {
    let type_name = type_name.trim().trim_end_matches("[]");
    src.user_definitions.user_defined_types
        .get(type_name)
        .and_then(|t| t.udt_members.clone())
        .or_else(|| {
            src.included_udo_files
                .values()
                .find_map(|file| file.user_defined_types.get(type_name).and_then(|t| t.udt_members.clone()))
        })
}

fn struct_member_items(src: &CompletionSources, scope: &Scope, ctx: &CursorContext) -> Option<Vec<CompletionItem>> {
    let chain = STRUCT_CHAIN.captures(ctx.before_prefix)?.get(1)?.as_str();
    let mut segments = chain.split('.').map(|s| s.split('[').next().unwrap_or(s));

    let mut type_name = variable_type(src, scope, segments.next()?)?;
    for member in segments {
        let members = struct_members(src, &type_name)?;
        type_name = members.into_iter().find(|(name, _)| name == member)?.1;
    }

    let owner = type_name.trim_end_matches("[]").to_string();
    let items = struct_members(src, &type_name)?
        .into_iter()
        .filter(|(name, _)| matches_prefix(name, ctx.prefix))
        .map(|(name, field_type)| CompletionItem {
            label: name,
            kind: Some(CompletionItemKind::FIELD),
            detail: Some(field_type),
            documentation: Some(Documentation::String(format!("Field of struct {}", owner))),
            ..Default::default()
        })
        .collect();
    Some(items)
}

fn macro_items(src: &CompletionSources, prefix: &str) -> Vec<CompletionItem> {
    let mut items = Vec::new();

    let local = src.user_definitions.user_defined_macros
        .values()
        .map(|m| (m, "User-defined macro".to_string()));
    let included = src.included_udo_files.values().flat_map(|file| {
        let source = file.path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        file.user_defined_macros
            .values()
            .map(move |m| (m, format!("User-defined macro from {}", source)))
    });

    for (m, documentation) in local.chain(included) {
        if !matches_prefix(&m.macro_name, prefix) {
            continue;
        }
        items.push(CompletionItem {
            label: m.macro_label.clone(),
            kind: Some(CompletionItemKind::CONSTANT),
            detail: Some(format!("#{}#", m.macro_values)),
            documentation: Some(Documentation::String(documentation)),
            filter_text: Some(m.macro_name.clone()),
            insert_text: Some(m.macro_name.clone()),
            ..Default::default()
        });
    }

    if let Some(omacros) = src.references.omacros_data.as_ref() {
        for (name, value) in omacros.iter().filter(|(name, _)| matches_prefix(name, prefix)) {
            items.push(CompletionItem {
                label: name.clone(),
                kind: Some(CompletionItemKind::CONSTANT),
                detail: Some(value.value.clone()),
                documentation: Some(Documentation::String(format!("equivalent to: {}", value.equivalent_to))),
                ..Default::default()
            });
        }
    }
    items
}

fn flag_items(src: &CompletionSources, ctx: &CursorContext, pos: &Position) -> Option<Vec<CompletionItem>> {
    let word_start = ctx.line_before.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
    let word = &ctx.line_before[word_start..];
    if !word.starts_with('-') {
        return None;
    }

    let range = Range {
        start: Position { line: pos.line, character: utf16_len(&ctx.line_before[..word_start]) },
        end: Position { line: pos.line, character: utf16_len(ctx.line_before) }
    };

    let mut items = Vec::new();
    let mut seen = HashSet::new();
    for data in src.references.oflag_data.as_ref()?.values() {
        for alternative in data.prefix.split(',') {
            let alternative = decode_entities(alternative.trim());
            let name_end = alternative
                .find(|c: char| matches!(c, '=' | ':' | '[' | '#') || c.is_whitespace())
                .unwrap_or(alternative.len());
            let name = &alternative[..name_end];
            if name.len() < 2 || !name.starts_with(word) {
                continue;
            }

            let new_text = if alternative[name_end..].starts_with('=') {
                format!("{}=", name)
            } else {
                name.to_string()
            };
            if !seen.insert(new_text.clone()) {
                continue;
            }

            items.push(CompletionItem {
                label: alternative.clone(),
                kind: Some(CompletionItemKind::PROPERTY),
                documentation: Some(Documentation::String(decode_entities(data.description.trim()))),
                filter_text: Some(new_text.clone()),
                sort_text: Some(name.to_string()),
                text_edit: Some(CompletionTextEdit::Edit(TextEdit { range, new_text })),
                ..Default::default()
            });
        }
    }
    Some(items)
}

pub fn complete(src: &CompletionSources, pos: &Position, context: Option<&CompletionContext>) -> Option<Vec<CompletionItem>> {
    let ctx = cursor_context(src.text, pos)?;
    if in_comment_or_string(ctx.line_before) || in_block_comment(src.tree, ctx.offset) {
        return None;
    }

    let region = region_at(src.text, ctx.offset, src.uri, src.doc_type);
    if region == Region::Options {
        return flag_items(src, &ctx, pos);
    }

    let trigger = ctx.before_prefix.chars().last();
    if trigger == Some('$') && matches!(region, Region::Orchestra | Region::Score) {
        return Some(macro_items(src, ctx.prefix));
    }

    if region != Region::Orchestra {
        return None;
    }

    let scope = scope_at(src, ctx.offset);
    match trigger {
        Some('.') => return struct_member_items(src, &scope, &ctx),
        Some(':') if is_type_annotation(ctx.before_prefix) => return Some(type_items(src, ctx.prefix)),
        _ => { }
    }

    // e.g. `-` typed in an expression
    let invoked = context.is_none_or(|c| c.trigger_kind == CompletionTriggerKind::INVOKED);
    if ctx.prefix.is_empty() && !invoked {
        return None;
    }

    // names of new instruments and opcodes
    if DEFINITION_LINE.is_match(ctx.line_before) {
        return None;
    }

    let mut items = Vec::new();
    let mut seen = HashSet::new();
    variable_items(src, &scope, &ctx, &mut items);
    udo_items(src, ctx.prefix, &mut items, &mut seen);
    opcode_items(src, ctx.prefix, &mut items, &mut seen);
    keyword_items(ctx.prefix, &mut items);
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::{ BodyOpCompletion, OpcodesData, OMacro };

    struct Doc {
        text: String,
        tree: Tree,
        doc_type: TreeType,
        uri: Url,
        definitions: UserDefinitions,
        typed_vars: HashMap<String, String>,
        references: CsoundJsonData
    }

    fn opcode(prefix: &str, body: &str) -> OpcodesData {
        OpcodesData {
            prefix: prefix.to_string(),
            body: BodyOpCompletion::SingleLine(body.to_string()),
            description: String::new()
        }
    }

    // `|` marks the cursor
    fn doc(file_name: &str, marked: &str) -> (Doc, Position) {
        let offset = marked.find('|').unwrap();
        let text = marked.replacen('|', "", 1);
        let before = &text[..offset];
        let line = before.matches('\n').count() as u32;
        let character = before.rsplit('\n').next().unwrap().encode_utf16().count() as u32;

        let uri = Url::parse(&format!("file:///tmp/{}", file_name)).unwrap();
        let parsed = parser::parse_doc(&text, None);
        let (typed_vars, definitions) = {
            let nodes = parser::iterate_tree(&parsed.tree, &text, &uri);
            (nodes.typed_vars, nodes.user_definitions)
        };

        let references = CsoundJsonData {
            opcodes_data: Some(HashMap::from([
                ("oscili".to_string(), opcode("oscili(xamp, xcps [, ifn, iphs])", "oscili")),
                ("outs".to_string(), opcode("outs(asig1, asig2)", "outs")),
                ("\\$NAME".to_string(), opcode("\\$NAME", "\\$NAME"))
            ])),
            omacros_data: Some(HashMap::from([
                ("M_PI".to_string(), OMacro { value: "3.14".to_string(), equivalent_to: "pi".to_string() })
            ])),
            oflag_data: Some(HashMap::from([
                ("-o FILE, --output=FILE".to_string(), opcode("-o FILE, --output=FILE", "-o")),
                ("-d, --nodisplays".to_string(), opcode("-d, --nodisplays", "-d"))
            ]))
        };

        let d = Doc { tree: parsed.tree, doc_type: parsed.tree_type, text, uri, definitions, typed_vars, references };
        (d, Position { line, character })
    }

    fn labels(file_name: &str, marked: &str, kind: CompletionTriggerKind) -> Option<Vec<String>> {
        let (d, pos) = doc(file_name, marked);
        let included = HashMap::new();
        let src = CompletionSources {
            text: &d.text,
            tree: &d.tree,
            uri: &d.uri,
            doc_type: &d.doc_type,
            user_definitions: &d.definitions,
            typed_vars: &d.typed_vars,
            included_udo_files: &included,
            references: &d.references
        };
        let context = CompletionContext { trigger_kind: kind, trigger_character: None };
        complete(&src, &pos, Some(&context)).map(|items| {
            let mut labels: Vec<String> = items.into_iter().map(|i| i.label).collect();
            labels.sort();
            labels
        })
    }

    fn invoked(file_name: &str, marked: &str) -> Option<Vec<String>> {
        labels(file_name, marked, CompletionTriggerKind::INVOKED)
    }

    #[test]
    fn variable_is_offered_between_definition_and_reassignment() {
        let got = invoked("a.orc", "instr 1\n  kAmp = 0.5\n  k|\n  kAmp = kAmp + 1\nendin\n").unwrap();
        assert!(got.contains(&"kAmp".to_string()), "{got:?}");
    }

    #[test]
    fn variable_is_not_offered_before_its_definition() {
        let got = invoked("a.orc", "instr 1\n  k|\n  kAmp = 0.5\nendin\n").unwrap();
        assert!(!got.contains(&"kAmp".to_string()), "{got:?}");
    }

    #[test]
    fn variables_of_other_instruments_are_not_offered() {
        let got = invoked("a.orc", "instr 1\n  kOther = 1\nendin\ninstr 2\n  k|\nendin\n").unwrap();
        assert!(!got.contains(&"kOther".to_string()), "{got:?}");
    }

    #[test]
    fn completion_works_inside_incomplete_call() {
        let got = invoked("a.orc", "instr 1\n  kAmp = 0.5\n  aOut = oscili(kA|\nendin\n").unwrap();
        assert_eq!(got, vec!["kAmp".to_string()]);
    }

    #[test]
    fn opcodes_and_local_udos_are_offered() {
        let got = invoked("a.orc", "opcode Oscbank, a, k\n  kf xin\n  xout a1\nendop\ninstr 1\n  aSig o|\nendin\n").unwrap();
        assert!(got.contains(&"oscili".to_string()), "{got:?}");
        assert!(got.contains(&"od".to_string()), "{got:?}");
        let got = invoked("a.orc", "opcode Oscbank, a, k\n  kf xin\n  xout a1\nendop\ninstr 1\n  aSig O|\nendin\n").unwrap();
        assert!(got.contains(&"Oscbank".to_string()), "{got:?}");
    }

    #[test]
    fn invalid_reference_names_are_skipped() {
        let got = invoked("a.orc", "instr 1\n  |\nendin\n").unwrap();
        assert!(!got.iter().any(|l| l.contains("NAME")), "{got:?}");
    }

    #[test]
    fn nothing_on_definition_lines_comments_and_strings() {
        assert_eq!(invoked("a.orc", "instr os|\nendin\n"), None);
        assert_eq!(invoked("a.orc", "instr 1\n  ; os|\nendin\n"), None);
        assert_eq!(invoked("a.orc", "instr 1\n  prints \"os|\"\nendin\n"), None);
    }

    #[test]
    fn nothing_after_trigger_character_in_expressions() {
        assert_eq!(labels("a.orc", "instr 1\n  kx = 1 -|\nendin\n", CompletionTriggerKind::TRIGGER_CHARACTER), None);
    }

    #[test]
    fn score_gets_no_opcodes() {
        let csd = "<CsoundSynthesizer>\n<CsInstruments>\ninstr 1\nendin\n</CsInstruments>\n<CsScore>\ni|\n</CsScore>\n</CsoundSynthesizer>\n";
        assert_eq!(invoked("a.csd", csd), None);
    }

    #[test]
    fn struct_members_after_dot() {
        let got = invoked("a.orc", "struct Pt x:k, y:k\ninstr 1\n  p:Pt init 0, 0\n  kv = p.|\nendin\n").unwrap();
        assert_eq!(got, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn no_struct_members_after_a_number() {
        assert_eq!(invoked("a.orc", "instr 1\n  kv = 0.|\nendin\n"), None);
    }

    #[test]
    fn types_after_colon() {
        let got = invoked("a.orc", "struct Pt x:k, y:k\ninstr 1\n  kv:|\nendin\n").unwrap();
        assert!(got.contains(&"k".to_string()) && got.contains(&"Pt".to_string()), "{got:?}");
        let got = invoked("a.orc", "instr 1\n  kv = 1 ? 2 :|\nendin\n");
        assert!(got.is_none_or(|g| !g.contains(&"Pt".to_string())));
    }

    #[test]
    fn macros_after_dollar() {
        let got = invoked("a.orc", "#define FOO #1#\ninstr 1\n  kv = $|\nendin\n").unwrap();
        assert_eq!(got, vec!["FOO".to_string(), "M_PI".to_string()]);
    }

    #[test]
    fn flags_in_options_replace_the_typed_dashes() {
        let csd = "<CsoundSynthesizer>\n<CsOptions>\n-odac --|\n</CsOptions>\n</CsoundSynthesizer>\n";
        let (d, pos) = doc("a.csd", csd);
        let included = HashMap::new();
        let src = CompletionSources {
            text: &d.text, tree: &d.tree, uri: &d.uri, doc_type: &d.doc_type,
            user_definitions: &d.definitions, typed_vars: &d.typed_vars,
            included_udo_files: &included, references: &d.references
        };
        let items = complete(&src, &pos, None).unwrap();
        let edits: Vec<(String, u32)> = items.iter().map(|i| match &i.text_edit {
            Some(CompletionTextEdit::Edit(e)) => (e.new_text.clone(), e.range.start.character),
            _ => panic!("missing text edit")
        }).collect();
        assert_eq!(edits.len(), 2, "{edits:?}");
        assert!(edits.contains(&("--output=".to_string(), 6)), "{edits:?}");
        assert!(edits.contains(&("--nodisplays".to_string(), 6)), "{edits:?}");
    }

    #[test]
    fn cursor_context_uses_utf16_columns() {
        let text = "; è\nkè = osc\n";
        let ctx = cursor_context(text, &Position { line: 1, character: 8 }).unwrap();
        assert_eq!(ctx.prefix, "osc");
        assert_eq!(ctx.offset, text.len() - 1);
    }
}
