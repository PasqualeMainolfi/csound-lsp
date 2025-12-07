use crate::parser;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{ Client, LanguageServer };
use std::collections::{ HashMap, HashSet };
use tokio::sync::RwLock;
use std::sync::Arc;


#[derive(Debug)]
pub struct Backend {
    client: Client,
    docs: Arc<RwLock<HashMap<Url, String>>>,
    opcodes: HashMap<String, String>,
    user_definitions: Arc<RwLock<parser::UserDefinitions>>,
    cached_typed_vars: Arc<RwLock<HashMap<String, String>>>
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let opcodes = parser::load_opcodes();
        Self {
            client,
            docs: Arc::new(RwLock::new(HashMap::new())),
            opcodes,
            user_definitions: Arc::new(RwLock::new(parser::UserDefinitions::new())),
            cached_typed_vars: Arc::new(RwLock::new(HashMap::new()))
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
                    trigger_characters: Some(vec![".".to_string()]),
                    work_done_progress_options: Default::default(),
                    all_commit_characters: None,
                    ..Default::default()
                }),
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
        let mut d = self.docs.write().await;
        d.insert(uri, text);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let mut diagnostics = Vec::new();
        let mut cached_diag: HashSet<(u32, u32, String)> = HashSet::new();

        if let Some(current_change) = params.content_changes.into_iter().next() {
            let text = current_change.text;
            let mut d = self.docs.write().await;
            d.insert(uri.clone(), text.clone());

            let mut local_ud = self.user_definitions.write().await;
            let tree = parser::parse_doc(&text);
            let nodes_to_diagnostics = parser::iterate_tree(&tree, &text, &mut local_ud);
            let mut cached_vars = self.cached_typed_vars.write().await;
            *cached_vars = nodes_to_diagnostics.typed_vars;

            for node in nodes_to_diagnostics.opcodes {
                let node_type = node.utf8_text(text.as_bytes()).unwrap();
                if !nodes_to_diagnostics.udo.contains(node_type) && !nodes_to_diagnostics.udt.contains(node_type) {
                    match self.opcodes.get(node_type) {
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

            for node in nodes_to_diagnostics.types {
                let type_identifier = parser::get_node_name(node, &text).unwrap();
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
                let node_name = parser::get_node_name(node.node, &text).unwrap();
                let message = match node.error_type {
                    parser::GErrors::Syntax => {
                        format!("Syntax error: <{}>", node_name)
                    },
                    parser::GErrors::ExplicitType => {
                        format!("Generic error, unknown Type identifier: <{}>", node_name)
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

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let pos = params.text_document_position_params.position;
        let uri = params.text_document_position_params.text_document.uri.clone();

        let docs = self.docs.read().await;
        let text = match docs.get(&uri) {
            Some(t) => t,
            None => {
                self.client.log_message(MessageType::ERROR, format!("No opcode text founded")).await;
                return Ok(None)
            }
        };

        let tree = parser::parse_doc(&text);

        if let Some(node) = parser::find_node_at_position(&tree, &pos) {
            let node_kind = node.kind();
            let node_type = node.utf8_text(text.as_bytes()).unwrap_or("???"); // opcode key

            self.client.log_message(MessageType::INFO,
                format!("HOVER DEBUG: Kind='{}', Text='{}', Parent='{}'",
                node_kind,
                parser::get_node_name(node, &text).unwrap_or_default(),
                node.parent().map(|p| p.kind()).unwrap_or("None")
            )).await;

            match node_kind {
                "opcode_name" => {
                    let local_udo = self.user_definitions.read().await;
                    if local_udo.user_defined_opcodes.contains_key(&node_type.to_string()) {
                        let ud = local_udo.user_defined_opcodes.get(&node_type.to_string()).unwrap();
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
                        if let Some(child_type_name) = parser::get_node_name(node, &text) {
                            let local_udt = self.user_definitions.read().await;
                            if local_udt.user_defined_types.contains_key(&child_type_name) {
                                let sd = local_udt.user_defined_types.get(&child_type_name).unwrap();
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
        Ok(None)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        self.client.log_message(MessageType::ERROR, "COMPLETION STARTED").await;
        let pos = params.text_document_position.position;
        let uri = params.text_document_position.text_document.uri.clone();

        let docs = self.docs.read().await;
        let text = match docs.get(&uri) {
            Some(t) => t,
            None => return Ok(None),
        };

        let tree = parser::parse_doc(&text);

        if let Some(node) = parser::find_node_at_position(&tree, &pos) {
            let mut variable_name = String::new();
            let mut curr_node = Some(node);
            while let Some(n) = curr_node {
                if n.kind() == "struct_access" {
                    if let Some(obj_node) = n.child_by_field_name("called_struct") {
                        variable_name = parser::get_node_name(obj_node, &text).unwrap_or_default();
                    }
                    break;
                }
                curr_node = n.parent();
            }
            if !variable_name.is_empty() {
                let local_vars = self.cached_typed_vars.read().await;
                if let Some(struct_type_name) = local_vars.get(&variable_name) {
                    let local_defs = self.user_definitions.read().await;
                    if let Some(udt) = local_defs.user_defined_types.get(struct_type_name) {
                        if let Some(ref members) = udt.udt_members {
                            let items: Vec<CompletionItem> = members
                                .iter()
                                .map(|(field_name, field_type)| {
                                    CompletionItem {
                                        label: field_name.clone(),
                                        kind: Some(CompletionItemKind::FIELD),
                                        detail: Some(format!(": {}", field_type)), // Mostra il tipo nel menu
                                        insert_text: Some(field_name.clone()),
                                        documentation: Some(Documentation::String(format!(
                                            "Field of struct '{}' (Type: {})",
                                            variable_name, struct_type_name
                                        ))),
                                        ..Default::default()
                                    }
                                })
                                .collect();
                            return Ok(Some(CompletionResponse::Array(items)));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}
