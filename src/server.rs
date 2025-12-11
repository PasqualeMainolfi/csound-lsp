use crate::parser;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{ Client, LanguageServer };
use tree_sitter::Tree;
use std::collections::{ HashMap, HashSet };
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug)]
pub struct CurrentDocument {
    pub text: String,
    pub tree: Tree,
    pub user_definition: parser::UserDefinitions,
    pub cached_typed_vars: HashMap<String, String>
}

#[derive(Debug)]
pub struct Backend {
    client: Client,
    document_state: Arc<RwLock<HashMap<Url, CurrentDocument>>>,
    opcodes: HashMap<String, String>,
    opcode_completion_list: Option<HashMap<String, parser::OpcodesData>>
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let opcodes = parser::load_opcodes();
        let opcode_completion_list = parser::read_opcode_data();
        Self {
            client,
            document_state: Arc::new(RwLock::new(HashMap::new())),
            opcodes,
            opcode_completion_list
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
                    trigger_characters: Some(vec![".".to_string(), ":".to_string()]),
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
        let tree = parser::parse_doc(&text);
        let mut d = self.document_state.write().await;
        d.insert(
            uri,
            CurrentDocument {
                text,
                tree,
                user_definition: parser::UserDefinitions::new(),
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
                let tree = parser::parse_doc(&text);
                doc.text = text.clone();
                doc.tree = tree;
                let nodes_to_diagnostics = parser::iterate_tree(&doc.tree, &doc.text, &mut doc.user_definition);
                doc.cached_typed_vars = nodes_to_diagnostics.typed_vars;

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
                    format!("HOVER DEBUG: Kind='{}', Text='{}', Parent='{}', id={}",
                    node_kind,
                    parser::get_node_name(node, &doc.text).unwrap_or_default(),
                    node.parent().map(|p| p.kind()).unwrap_or("None"),
                    node.id()
                )).await;

                match node_kind {
                    "opcode_name" => {
                        if let Some(ud) = doc.user_definition.user_defined_opcodes.get(&node_type.to_string()) {
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
                                if let Some(sd) = doc.user_definition.user_defined_types.get(&child_type_name) {
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
                                if let Some(udt) = doc.user_definition.user_defined_types.get(&struct_type_name.clone()) {
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
                                        for (_, udt) in doc.user_definition.user_defined_types.iter() {
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
                                    _ => {
                                        if let Some(p) = wnode.parent() {
                                            let pkind = p.kind();
                                            if pkind != "modern_udo_inputs" && wnode.kind() != "legacy_udo_args" {
                                                if let Some(ref list) = self.opcode_completion_list {
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
}
