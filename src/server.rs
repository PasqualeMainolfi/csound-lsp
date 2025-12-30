use crate::parser;

use serde_json::Value;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{ Client, LanguageServer };
use tree_sitter::{ Tree, Query, Parser };
use std::collections::{ HashMap, HashSet };
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use std::sync::Arc;

pub struct CurrentDocument {
    pub text: String,
    pub tree: Tree,
    pub query: Query,
    pub query_injection: Query,
    pub user_definitions: parser::UserDefinitions,
    pub cached_typed_vars: HashMap<String, String>,
    pub csound_parser: Parser,
    pub py_query: parser::ExternalQuery,
    pub html_query: parser::ExternalQuery
}

pub struct Backend {
    client: Client,
    document_state: Arc<RwLock<HashMap<Url, CurrentDocument>>>,
    opcodes: HashMap<String, String>,
    json_reference_completion_list: parser::CsoundJsonData,
    manual_temp_path: Arc<RwLock<PathBuf>>
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let opcodes = parser::load_opcodes();
        let json_reference_completion_list = parser::read_csound_json_data();
        Self {
            client,
            document_state: Arc::new(RwLock::new(HashMap::new())),
            opcodes,
            json_reference_completion_list,
            manual_temp_path: Arc::new(RwLock::new(PathBuf::new()))
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        let mut temp_dir = std::env::temp_dir();
        temp_dir.push("csound_html_manual");

        if let Err(e) = parser::extract_manual(temp_dir.to_str().unwrap()) {
            self.client.log_message(MessageType::WARNING, format!("Failed to load Csound offline Manual {}", e)).await;
        }

        let mut mp = self.manual_temp_path.write().await;
        *mp = temp_dir;

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![
                        ".".to_string(),
                        ":".to_string(),
                        "$".to_string(),
                        "-".to_string()
                    ]),
                    work_done_progress_options: Default::default(),
                    all_commit_characters: None,
                    ..Default::default()
                }),
                semantic_tokens_provider: Some(SemanticTokensServerCapabilities::SemanticTokensOptions(
                    SemanticTokensOptions {
                        legend: parser::get_token_lengend(),
                        full: Some(SemanticTokensFullOptions::Bool(true)),
                        ..Default::default()
                    }
                )),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![
                        "csound-lsp.run_file".into(),
                        "csound-lsp.to_audio_file".into(),
                        "csound-lsp.open_manual".into()
                    ],
                    ..Default::default()
                }),
                code_lens_provider: Some(CodeLensOptions {
                    resolve_provider: Some(false)
                }),
                document_on_type_formatting_provider: Some(DocumentOnTypeFormattingOptions {
                    first_trigger_character: "}".to_string(),
                    more_trigger_character: Some(vec![
                        "n".to_string(),
                        "p".to_string(),
                        "i".to_string(),
                        "d".to_string(),
                        "\n".to_string()
                    ])
                }),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Csound LSP initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        let parsed_tree = parser::parse_doc(&text);
        let mut d = self.document_state.write().await;
        d.insert(
            uri,
            CurrentDocument {
                text,
                tree: parsed_tree.tree,
                query: parsed_tree.query,
                query_injection: parsed_tree.query_injection,
                user_definitions: parser::UserDefinitions::new(),
                cached_typed_vars: HashMap::new(),
                csound_parser: parsed_tree.csound_parser,
                py_query: parser::ExternalQuery { parser: parsed_tree.py_parser, query: parsed_tree.query_py },
                html_query: parser::ExternalQuery { parser: parsed_tree.html_parser, query: parsed_tree.query_html }
            }
        );
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.document_state.write().await.remove(&uri);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;

        if let Some(current_change) = params.content_changes.into_iter().next() {
            let mut diagnostics = Vec::new();
            let mut cached_diag: HashSet<(u32, u32, String)> = HashSet::new();
            let mut d = self.document_state.write().await;

            if let Some(doc) = d.get_mut(&uri) {
                let text = current_change.text;
                let parsed_tree = parser::parse_doc(&text);
                doc.text = text.clone();
                doc.tree = parsed_tree.tree;
                doc.query = parsed_tree.query;
                doc.query_injection = parsed_tree.query_injection;
                let nodes_to_diagnostics = parser::iterate_tree(&doc.tree, &doc.text);
                doc.cached_typed_vars = nodes_to_diagnostics.typed_vars;
                doc.user_definitions = nodes_to_diagnostics.user_definitions;

                parser::get_semantic_tokens(&doc.query, &doc.tree, &text, None);

                for var in &doc.user_definitions.unused_vars {
                    if let Some(finded_node) = doc.tree.root_node().descendant_for_byte_range(var.node_location, var.node_location) {
                        let parent_finded_kind = finded_node.parent().map(|p| p.kind()).unwrap_or("");
                        self.client.log_message(MessageType::INFO,
                            format!("UNUSED DEBUG: Kind='{}', parent={}, Text='{}', calls={}, scope={:?}",
                            finded_node.kind(),
                            finded_node.parent().unwrap().kind(),
                            var.var_name,
                            var.var_calls,
                            var.var_scope
                        )).await;

                        let diag = Diagnostic {
                            range: parser::get_node_range(&finded_node),
                            severity: Some(DiagnosticSeverity::HINT),
                            source: Some("csound-lsp".into()),
                            message: {
                                match parent_finded_kind {
                                    "label_statement" => "Unused label".to_string(),
                                    "macro_name" => "Unused macro".to_string(),
                                    _ => "Unused variable".to_string(),
                                }
                            },
                            tags: Some(vec![DiagnosticTag::UNNECESSARY]),
                            ..Default::default()
                        };
                        if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                            diagnostics.push(diag);
                        }
                    }
                }

                for var in &doc.user_definitions.undefined_vars {
                    if let Some(finded_node) = doc.tree.root_node().descendant_for_byte_range(var.node_location, var.node_location) {
                        let parent_finded_kind = finded_node.parent().map(|p| p.kind()).unwrap_or("");
                        self.client.log_message(MessageType::INFO,
                                format!("UNDEFINED DEBUG: Kind='{}', parent={}, Text='{}', calls={}, scope={:?}",
                            finded_node.kind(),
                            finded_node.parent().unwrap().kind(),
                            var.var_name,
                            var.var_calls,
                            var.var_scope
                        )).await;

                        for node_range in &var.references {
                            let diag = Diagnostic {
                                range: *node_range,
                                severity: Some(DiagnosticSeverity::ERROR),
                                source: Some("csound-lsp".into()),
                                message: {
                                    match parent_finded_kind {
                                        "label_statement" => "Undefined label".to_string(),
                                        "macro_usage" => "Undefined macro".to_string(),
                                        _ => "Undefined variable".to_string(),
                                    }
                                },
                                ..Default::default()
                            };
                            if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                diagnostics.push(diag);
                            }
                        }
                    }
                }

                for node in nodes_to_diagnostics.opcodes {
                    if let Some(nt) = parser::get_node_name(node, &doc.text) {
                        let node_type = nt.split_once(":").map(|(prefix, _)| prefix.to_string()).unwrap_or(nt);
                        if !nodes_to_diagnostics.udo.contains(&node_type) && !nodes_to_diagnostics.udt.contains(&node_type) {
                            match self.opcodes.get(&node_type) {
                                Some(_) => {},
                                None => {
                                    let diag = Diagnostic {
                                        range: parser::get_node_range(&node),
                                        severity: Some(DiagnosticSeverity::ERROR),
                                        source: Some("csound-lsp".into()),
                                        message: format!("Unknown opcode: <{}>", node_type),
                                        ..Default::default()
                                    };
                                    if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                        diagnostics.push(diag);
                                    }
                                }
                            }
                        }
                    }
                }

                for node in nodes_to_diagnostics.types {
                    let type_identifier = parser::get_node_name(node, &doc.text).unwrap();
                    if !parser::is_valid_type(&type_identifier) && !nodes_to_diagnostics.udt.contains(&type_identifier) {
                        let diag = Diagnostic {
                            range: parser::get_node_range(&node),
                            severity: Some(DiagnosticSeverity::ERROR),
                            source: Some("csound-lsp".into()),
                            message: format!("Unknown type identifier: <{}>", type_identifier),
                            ..Default::default()
                        };
                        if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                            diagnostics.push(diag);
                        }
                    }
                }

                for node in nodes_to_diagnostics.generic_errors {
                    let node_name = parser::get_node_name(node.node, &doc.text).unwrap();
                    let message = match node.error_type {
                        parser::GErrors::Syntax => {
                            format!("Syntax error: <{}>", node_name)
                        },
                        parser::GErrors::ExplicitType => {
                            format!("Unknown type identifier: <{}>", node_name)
                        },
                        parser::GErrors::ScoreStatement => {
                            format!("Unknown score statement <{}>", node_name)
                        },
                        parser::GErrors::MissingPfield => {
                            format!("Missing mandatory p-fields (p1, p2, p3)")
                        }
                    };
                    let diag = Diagnostic {
                        range: parser::get_node_range(&node.node),
                        severity: Some(DiagnosticSeverity::ERROR),
                        source: Some("csound-lsp".into()),
                        message: message,
                        ..Default::default()
                    };
                    if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                        diagnostics.push(diag);
                    }
                }
            }
            self.client.publish_diagnostics(uri, diagnostics, None).await;
        }

    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri.clone();
        let pos = params.text_document_position_params.position;

        let dc = self.document_state.read().await;
        if let Some(doc) = dc.get(&uri) {
            if let Some(node) = parser::find_node_at_position(&doc.tree, &pos) {
                let node_kind = node.kind();
                let node_type = node.utf8_text(doc.text.as_bytes()).unwrap_or("???"); // opcode key

                self.client.log_message(MessageType::INFO,
                    format!("HOVER DEBUG: Kind='{}', Text='{}', Parent='{}', scope={:?}",
                    node_kind,
                    parser::get_node_name(node, &doc.text).unwrap_or_default(),
                    node.parent().map(|p| p.kind()).unwrap_or("None"),
                    parser::find_scope(node, &doc.text)
                )).await;

                match node_kind {
                    "opcode_name" => {
                        if let Some(ud) = doc.user_definitions.user_defined_opcodes.get(&node_type.to_string()) {
                            let md = format!("## User-Defined Opcode\n```\n{}\n```", ud);
                            return Ok(Some(Hover {
                                contents: HoverContents::Markup(MarkupContent {
                                        kind: MarkupKind::Markdown,
                                        value: md,
                                    }),
                                    range: None,
                                })
                            )
                        }

                        if let Some(reference) = self.opcodes.get(node_type) {
                            return Ok(Some(Hover {
                                contents: HoverContents::Markup(MarkupContent {
                                        kind: MarkupKind::Markdown,
                                        value: reference.clone(),
                                    }),
                                    range: None,
                                })
                            )
                        } else {
                            self.client.log_message(MessageType::WARNING, format!("Manual not found for opcode {}", node_type)).await;
                        }
                    },
                    "identifier" => {
                        let is_type = node.parent()
                            .map(|p| p.kind() == "typed_identifier" || p.kind() == "type_identifier")
                            .unwrap_or(false);

                        if is_type {
                            if let Some(child_type_name) = parser::get_node_name(node, &doc.text) {
                                if let Some(sd) = doc.user_definitions.user_defined_types.get(&child_type_name) {
                                    let md = format!("## User-Defined Type\n```\n{}\n```", sd.udt_format);
                                    return Ok(Some(Hover {
                                        contents: HoverContents::Markup(MarkupContent {
                                                kind: MarkupKind::Markdown,
                                                value: md,
                                            }),
                                            range: None,
                                        })
                                    )
                                }

                                let splitted_name = node_type.split_once(":").map(|(p, _)| p).unwrap_or(node_type);
                                if let Some(reference) = self.opcodes.get(splitted_name) {
                                    return Ok(Some(Hover {
                                        contents: HoverContents::Markup(MarkupContent {
                                                kind: MarkupKind::Markdown,
                                                value: reference.clone(),
                                            }),
                                            range: None,
                                        })
                                    )
                                }
                            }

                        }
                    },
                    _ => {}
                }
            }
        }
        Ok(None)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let pos = params.text_document_position.position;
        let uri = params.text_document_position.text_document.uri.clone();

        let dc = self.document_state.read().await;
        if let Some(doc) = dc.get(&uri) {
            if let Some(node) = parser::find_node_at_position(&doc.tree, &pos) {
                match node.kind() {
                    "struct_access" => {
                        let mut variable_name = String::new();
                        if let Some(obj_node) = node.child_by_field_name("called_struct") {
                            variable_name = parser::get_node_name(obj_node, &doc.text).unwrap_or_default();
                        }
                        if !variable_name.is_empty() {
                            if let Some(struct_type_name) = doc.cached_typed_vars.get(&variable_name) {
                                if let Some(udt) = doc.user_definitions.user_defined_types.get(&struct_type_name.clone()) {
                                    if let Some(ref members) = udt.udt_members {
                                        let items: Vec<CompletionItem> = members
                                            .iter()
                                            .map(|(field_name, field_type)| {
                                                CompletionItem {
                                                    label: field_name.clone(),
                                                    kind: Some(CompletionItemKind::FIELD),
                                                    detail: Some(format!(": {}", field_type)),
                                                    insert_text: Some(field_name.clone()),
                                                    documentation: Some(Documentation::String(format!(
                                                        "Field of struct '{}' (Type: {})",
                                                        variable_name, struct_type_name
                                                    ))),
                                                    ..Default::default()
                                                }
                                            })
                                            .collect();
                                        return Ok(Some(CompletionResponse::Array(items)))
                                    }
                                }
                            }
                        }
                        return Ok(None)
                    },
                    _ => {
                        if let Some(wnode) = parser::find_node_at_cursor(&doc.tree, &pos, &doc.text) {
                            let op_name = parser::get_node_name(wnode, &doc.text).unwrap_or("".to_string());
                            let p = wnode.parent().map(|p| p.kind()).unwrap();
                            self.client.log_message(MessageType::INFO,
                                format!("COMPLETION DEBUG: Name={} Kind={} Parent={}", op_name, wnode.kind(), p)).await;

                            match wnode.kind() {
                                ":" => {
                                    let mut v = HashSet::new();
                                    let types = vec!["a", "i", "k", "b", "S", "f", "w", "InstrDef", "Instr", "Opcode", "Complex"];
                                    v.extend(types);
                                    for (_, udt) in doc.user_definitions.user_defined_types.iter() {
                                        v.insert(udt.udt_name.as_str());
                                    }

                                    let total_types: Vec<&str> = v.into_iter().collect();
                                    let items: Vec<CompletionItem> = total_types
                                        .iter()
                                        .map(|ty| {
                                            CompletionItem {
                                                label: ty.to_string(),
                                                kind: Some(CompletionItemKind::FIELD),
                                                detail: Some(format!("{}", ty)),
                                                insert_text: Some(ty.to_string()),
                                                documentation: Some(Documentation::String(format!("Data type '{}'", ty))),
                                                ..Default::default()
                                            }
                                        })
                                        .collect();
                                    return Ok(Some(CompletionResponse::Array(items)))
                                },
                                "$" => {
                                    let mut items = Vec::new();
                                    for (_, value) in doc.user_definitions.user_defined_macros.iter() {
                                        items.push(CompletionItem {
                                            label: value.macro_label.clone(),
                                            kind: Some(CompletionItemKind::FIELD),
                                            detail: Some(format!("# {} #", value.macro_values)),
                                            insert_text: Some(value.macro_name.clone()),
                                            documentation: Some(Documentation::String("user defined macro".to_string())),
                                            ..Default::default()
                                            }
                                        );
                                    }
                                    if let Some(omacros) = &self.json_reference_completion_list.omacros_data {
                                        for (omacro, macro_value) in omacros {
                                            items.push(CompletionItem {
                                                label: omacro.clone(),
                                                kind: Some(CompletionItemKind::FIELD),
                                                detail: Some(format!("value: {}", macro_value.value)),
                                                insert_text: Some(omacro.clone()),
                                                documentation: Some(Documentation::String(format!("equivalent to: {}", macro_value.equivalent_to))),
                                                ..Default::default()
                                                }
                                            );
                                        }
                                    }
                                    if !items.is_empty() {
                                        return Ok(Some(CompletionResponse::Array(items)))
                                    }
                                    return Ok(None)
                                },
                                "flag_identifier" => {
                                    if let Some(ref list) = self.json_reference_completion_list.oflag_data {
                                        let mut items = Vec::new();
                                        for (_, data) in list {
                                            let data_body = data.get_string_from_body();
                                            let slice_body: String = String::from(&data_body[1..]);
                                            items.push(CompletionItem {
                                                label: data.prefix.clone(),
                                                kind: Some(CompletionItemKind::FIELD),
                                                insert_text: Some(slice_body),
                                                documentation: Some(Documentation::String(format!("{}", data.description))),
                                                ..Default::default()
                                                }
                                            )
                                        }
                                        return Ok(Some(CompletionResponse::Array(items)))
                                    }
                                    return Ok(None)
                                }
                                _ => {
                                    if !op_name.is_empty() {
                                        if let Some(p) = wnode.parent() {
                                            let pkind = p.kind();
                                            if
                                            {
                                                wnode.kind() != "legacy_udo_args" &&
                                                pkind != "modern_udo_inputs"      &&
                                                pkind != "flag_content"           &&
                                                pkind != "struct_access"          &&
                                                pkind != "ERROR"
                                            }
                                            {
                                                if let Some(ref list) = self.json_reference_completion_list.opcodes_data {
                                                    let mut items = Vec::new();
                                                    for (n, data) in list {
                                                        if n.starts_with(&op_name) {
                                                            let data_body = data.get_string_from_body();
                                                            let is_snip = data_body.contains("$");

                                                            items.push(CompletionItem {
                                                                label: data.prefix.clone(),
                                                                kind: Some(if is_snip {
                                                                        CompletionItemKind::SNIPPET
                                                                    } else {
                                                                        CompletionItemKind::FUNCTION
                                                                    }
                                                                ),
                                                                insert_text: Some(data_body.clone()),
                                                                insert_text_format: Some(if is_snip {
                                                                        InsertTextFormat::SNIPPET
                                                                    } else {
                                                                        InsertTextFormat::PLAIN_TEXT
                                                                    }
                                                                ),
                                                                documentation: Some(Documentation::String(format!("{}", data.description))),
                                                                ..Default::default()
                                                                }
                                                            )
                                                        }
                                                    }
                                                    return Ok(Some(CompletionResponse::Array(items)))
                                                }
                                                return Ok(None)
                                            }
                                        }
                                        return Ok(None)
                                    }
                                }
                            }
                        }
                    },
                }
            }
            return Ok(None)
        }
        return Ok(None)
    }

    async fn semantic_tokens_full(&self, params: SemanticTokensParams) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;
        let mut dc = self.document_state.write().await;
        if let Some(doc) = dc.get_mut(&uri) {
            let mut st = parser::get_semantic_tokens(&doc.query, &doc.tree, &doc.text, None);
            let inj = parser::get_injections(&doc.query_injection, &doc.tree, &doc.text, &mut doc.csound_parser, &doc.query, &mut doc.py_query, &mut doc.html_query);

            st.extend(inj);
            let stokens = parser::get_delta_pos(&mut st);

            return Ok(Some(SemanticTokensResult::Tokens(SemanticTokens{
                result_id: None, data: stokens
            })))
        }
        Ok(None)
    }

    async fn execute_command(&self, params: ExecuteCommandParams) -> Result<Option<Value>> {
        let cmd = params.command.as_str();
        match cmd {
            "csound-lsp.run_file" | "csound-lsp.to_audio_file" => {
                let mut file_paths:Vec<String> = Vec::new();
                for args in &params.arguments {
                    match args {
                        Value::String(s) => file_paths.push(s.clone()),
                        Value::Array(paths) => {
                            for p in paths {
                                if let Some(path) = p.as_str() {
                                    file_paths.push(path.to_string());
                                }
                            }
                        },
                        _ => { }
                    }
                }

                if cmd == "csound-lsp.run_file" {
                    return Ok(Some(serde_json::json!({
                        "action": "run csound file",
                        "exec": "csound",
                        "args": "-o dac",
                        "path": file_paths
                    })))
                }

                if !file_paths.is_empty() {
                    let file_name = Path::new(&file_paths[0]).file_stem().unwrap();
                    return Ok(Some(serde_json::json!({
                        "action": "save as audio file",
                        "exec": "csound",
                        "args": format!("-o {}.wav", file_name.to_string_lossy()),
                        "path": file_paths
                    })))
                } else {
                    return Ok(None)
                }
            },
            "csound-lsp.open_manual" => {
                let p = self.manual_temp_path.read().await;

                return Ok(Some(serde_json::json!({
                    "action": "open html csound manual",
                    "exec": "",
                    "args": "",
                    "path": p.to_string_lossy()
                })))
            }
            _ => { return Ok(None) }
        }
    }

    async fn code_lens(&self, _: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        let mut lense = Vec::new();

        lense.push(CodeLens {
            range: Range {
                start: Position { line: 0, character: 0 },
                end: Position { line: 0, character: 0 }
            },
            command: Some(Command {
                title: "📓 Csound Manual".into(),
                command: "csound.openManual".into(),
                arguments: None
            }),
            data: None
        });

        lense.push(CodeLens {
            range: Range {
                start: Position { line: 0, character: 0 },
                end: Position { line: 0, character: 0 }
            },
            command: Some(Command {
                title: "▶ Run".into(),
                command: "csound.runFile".to_string(),
                arguments: Some(vec![])
            }),
            data: None
        });

        lense.push(CodeLens {
            range: Range {
                start: Position { line: 0, character: 0 },
                end: Position { line: 0, character: 0 }
            },
            command: Some(Command {
                title: "⏹ Stop".into(),
                command: "csound.stopExecution".to_string(),
                arguments: Some(vec![])
            }),
            data: None
        });

        lense.push(CodeLens {
            range: Range {
                start: Position { line: 0, character: 0 },
                end: Position { line: 0, character: 0 }
            },
            command: Some(Command {
                title: "🔊 To Audio File".into(),
                command: "csound.saveAsAudioFile".to_string(),
                arguments: Some(vec![])
            }),
            data: None
        });

        Ok(Some(lense))
    }

    async fn on_type_formatting(&self, params: DocumentOnTypeFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;

        let dc = self.document_state.read().await;
        if let Some(doc) = dc.get(&uri) {
            let line_index = position.line as usize;
            let line_text = doc.text.lines().nth(line_index).unwrap_or("");
            let current_line_size = line_text.len() - line_text.trim_start().len();
            let current_indent_str = &line_text[..current_line_size];

            let tab_size = params.options.tab_size as usize;
            let indent_level = parser::make_indent(&doc.tree, &doc.text, position.line as usize);
            let indent = " ".repeat(indent_level * tab_size);

            if current_indent_str == indent {
                return Ok(None);
            }

            return Ok(Some(vec![
                TextEdit {
                    range: Range {
                        start: Position::new(position.line, 0),
                        end: Position::new(position.line, current_line_size as u32)
                    },
                    new_text: indent
                }
            ]))
        }
        Ok(None)
    }
}
