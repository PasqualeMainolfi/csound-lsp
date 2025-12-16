use crate::parser;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{ Client, LanguageServer };
use tree_sitter::{ Tree, Query };
use std::collections::{ HashMap, HashSet };
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug)]
pub struct CurrentDocument {
    pub text: String,
    pub tree: Tree,
    pub query: Query,
    pub user_definitions: parser::UserDefinitions,
    pub cached_typed_vars: HashMap<String, String>
}

#[derive(Debug)]
pub struct Backend {
    client: Client,
    document_state: Arc<RwLock<HashMap<Url, CurrentDocument>>>,
    opcodes: HashMap<String, String>,
    json_reference_completion_list: parser::CsoundJsonData
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let opcodes = parser::load_opcodes();
        let json_reference_completion_list = parser::read_csound_json_data();
        Self {
            client,
            document_state: Arc::new(RwLock::new(HashMap::new())),
            opcodes,
            json_reference_completion_list
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
                completion_provider: Some(CompletionOptions {
                    resolve_provider: Some(false),
                    trigger_characters: Some(vec![".".to_string(), ":".to_string(), "$".to_string() ]),
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
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "CSound LSP initialized!")
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
                user_definitions: parser::UserDefinitions::new(),
                cached_typed_vars: HashMap::new()
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
                let parses_tree = parser::parse_doc(&text);
                doc.text = text.clone();
                doc.tree = parses_tree.tree;
                doc.query = parses_tree.query;
                let nodes_to_diagnostics = parser::iterate_tree(&doc.tree, &doc.text);
                doc.cached_typed_vars = nodes_to_diagnostics.typed_vars;
                doc.user_definitions = nodes_to_diagnostics.user_definitions;

                parser::get_semantic_tokens(&doc.query, &doc.tree, &text);

                for var in &doc.user_definitions.unused_vars {
                    if let Some(finded_node) = doc.tree.root_node().descendant_for_byte_range(var.node_location, var.node_location) {

                        let diag = Diagnostic {
                            range: parser::get_node_range(&finded_node),
                            severity: Some(DiagnosticSeverity::WARNING),
                            source: Some("csound-lsp".into()),
                            message: "Unused variable".to_string(),
                            ..Default::default()
                        };
                        if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                            diagnostics.push(diag);
                        }
                    }
                }

                for var in &doc.user_definitions.undefined_vars {
                    if let Some(finded_node) = doc.tree.root_node().descendant_for_byte_range(var.node_location, var.node_location) {

                        for node_range in &var.references {
                            let diag = Diagnostic {
                                range: *node_range,
                                severity: Some(DiagnosticSeverity::ERROR),
                                source: Some("csound-lsp".into()),
                                message: "Undefined variable".to_string(),
                                ..Default::default()
                            };
                            if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                diagnostics.push(diag);
                            }
                        }
                    }
                }

                for node in nodes_to_diagnostics.opcodes {
                    if let Some(node_type) = parser::get_node_name(node, &doc.text){
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
                            format!("Unknown score statement")
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
                            // self.client.log_message(MessageType::INFO,
                            //     format!("COMPLETION DEBUG: Name='{}' Kind={}", op_name, wnode.kind())).await;

                            if !op_name.is_empty() {
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
                                    _ => {
                                        if let Some(p) = wnode.parent() {
                                            let pkind = p.kind();
                                            if pkind != "modern_udo_inputs" && wnode.kind() != "legacy_udo_args" {
                                                if let Some(ref list) = self.json_reference_completion_list.opcodes_data {
                                                    let mut items = Vec::new();
                                                    for (n, data) in list {
                                                        if n.starts_with(&op_name) {
                                                            let data_body = match &data.body {
                                                                parser::BodyOpCompletion::SingleLine(s) => s.clone(),
                                                                parser::BodyOpCompletion::MultipleLine(arr) => arr.join("\n")
                                                            };

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
                                    }
                                }
                            }
                            return Ok(None)
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
        let dc = self.document_state.read().await;
        if let Some(doc) = dc.get(&uri) {
            let st = parser::get_semantic_tokens(&doc.query, &doc.tree, &doc.text);
            return Ok(Some(SemanticTokensResult::Tokens(SemanticTokens{
                result_id: None, data: st
            })))
        }
        Ok(None)
    }
}
