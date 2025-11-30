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
        let n_opcodes = self.opcodes.len();
        if n_opcodes == 0 {
            self.client.log_message(MessageType::INFO, format!("LSP started number of opcodes loaded inmemory: {}", n_opcodes)).await;
        }

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                hover_provider: Some(HoverProviderCapability::Simple(true)),
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
            let node_type = node.utf8_text(text.as_bytes()).unwrap_or("???");

            self.client.log_message(MessageType::INFO, format!("Cursor on: point {}, type: {}", node_kind, node_type)).await;

            if node.kind() == "opcode_name" {
                let opcode_key = node.utf8_text(text.as_bytes()).unwrap();
                if let Some(reference) = self.opcodes.get(opcode_key) {
                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                                kind: MarkupKind::Markdown,
                                value: reference.clone(),
                            }),
                            range: None,
                        })
                    )
                } else {
                    self.client.log_message(MessageType::WARNING, format!("Manual not found for opcode {}", opcode_key)).await;
                }
            }
        } else {
            self.client.log_message(MessageType::ERROR, format!("No node founded")).await;
        }
        Ok(None)
    }
}
