use crate::parser;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{ Client, LanguageServer };
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;


#[derive(Debug)]
pub struct Backend {
    client: Client,
    docs: Arc<RwLock<HashMap<Url, String>>>,
    opcodes: HashMap<String, String>
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let opcodes = parser::load_opcodes();
        Self {
            client,
            docs: Arc::new(RwLock::new(HashMap::new())),
            opcodes
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

        if let Some(current_change) = params.content_changes.into_iter().next() {
            let text = current_change.text;
            let mut d = self.docs.write().await;
            d.insert(uri, text);
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let pos = params.text_document_position_params.position;
        let uri = params.text_document_position_params.text_document.uri.clone();

        let docs = self.docs.read().await;
        let text = match docs.get(&uri) {
            Some(t) => t,
            None => {
                self.client.log_message(MessageType::ERROR, format!("No opcode text founded1")).await;
                return Ok(None)
            }
        };

        let tree = parser::parse_doc(&text);


        if let Some(node) = parser::find_node_at_position(&tree, &pos) {
            let node_kind = node.kind();
            let node_type = node.utf8_text(text.as_bytes()).unwrap_or("???"); // opcode key

            if node_kind == "opcode_name" {
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
            }
        }
        Ok(None)
    }
}
