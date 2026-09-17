use crate::parser::{ UdoType, VarDataType };
use crate::{
    assets, completion, parser, resolve_pulgins, resolve_udos, utils
};

use ropey::Rope;
use serde_json::Value;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{ Client, LanguageServer };
use tree_sitter::{ InputEdit, Tree };
use tokio::sync::RwLock;
use std::{
    collections::{ HashMap, HashSet },
    path::{ Path, PathBuf },
    sync::{ Arc, Mutex, atomic::{ AtomicBool, Ordering } }
};

const GLOBAL_TEMP_DIR: &str = "csound-lsp_temp_folder";

pub struct CurrentDocument {
    pub text: Rope,
    pub doc_type: parser::TreeType,
    pub tree: Tree,
    pub user_definitions: parser::UserDefinitions,
    pub cached_typed_vars: HashMap<String, String>,
    pub cached_included_udo_files: HashMap<String, resolve_udos::UdoFile>,
    // behind a mutex so that read-only requests (semantic tokens) can use them
    pub internal_parsers: Mutex<parser::InternalParsers>,
}

impl CurrentDocument {
    pub fn new(text: &str) -> Self {
        let mut parsers = parser::load_parsers();
        let parsed = parser::parse_with(&mut parsers.csound_parser, text, None);
        Self {
            text: Rope::from_str(text),
            doc_type: parsed.tree_type,
            tree: parsed.tree,
            user_definitions: parser::UserDefinitions::new(),
            cached_typed_vars: HashMap::new(),
            cached_included_udo_files: HashMap::new(),
            internal_parsers: Mutex::new(parsers)
        }
    }

    fn parsers(&mut self) -> &mut parser::InternalParsers {
        self.internal_parsers.get_mut().unwrap_or_else(|e| e.into_inner())
    }
}

// Applies the changes to the text and the tree, then reparses once.
pub fn get_incremental_parsing(doc: &mut CurrentDocument, content_changes: &Vec<TextDocumentContentChangeEvent>) {
    if content_changes.is_empty() {
        return;
    }

    let mut full_reparse = false;
    for change in content_changes {
        let Some(range) = change.range else {
            doc.text = Rope::from_str(&change.text);
            full_reparse = true;
            continue;
        };

        let start_char = utils::lsp_position_to_char(&doc.text, &range.start);
        let old_end_char = utils::lsp_position_to_char(&doc.text, &range.end).max(start_char);

        let start_byte = doc.text.char_to_byte(start_char);
        let old_end_byte = doc.text.char_to_byte(old_end_char);
        let start_position = utils::char_to_point(&doc.text, start_char);
        let old_end_position = utils::char_to_point(&doc.text, old_end_char);

        doc.text.remove(start_char..old_end_char);
        doc.text.insert(start_char, &change.text);

        let new_end_char = start_char + change.text.chars().count();
        doc.tree.edit(&InputEdit {
            start_byte,
            old_end_byte,
            new_end_byte: start_byte + change.text.len(),
            start_position,
            old_end_position,
            new_end_position: utils::char_to_point(&doc.text, new_end_char)
        });
    }

    let text = doc.text.to_string();
    let old_tree = if full_reparse { None } else { Some(doc.tree.clone()) };
    let parsed = parser::parse_with(&mut doc.parsers().csound_parser, &text, old_tree.as_ref());
    doc.tree = parsed.tree;
    doc.doc_type = parsed.tree_type;
}

// Edit that re-indents `line`, or None when the indentation is already right.
pub fn indent_edit(text: &Rope, tree: &Tree, line: usize, options: &FormattingOptions) -> Option<TextEdit> {
    if line >= text.len_lines() {
        return None;
    }
    let line_text = text.line(line).to_string();
    let content = line_text.trim_end_matches(['\n', '\r']);
    let current_indent = &content[..content.len() - content.trim_start_matches([' ', '\t']).len()];

    let indent_level = parser::make_indent(tree, &text.to_string(), line);
    let indent = if options.insert_spaces {
        " ".repeat(indent_level * options.tab_size as usize)
    } else {
        "\t".repeat(indent_level)
    };

    if current_indent == indent {
        return None;
    }

    Some(TextEdit {
        range: Range {
            start: Position::new(line as u32, 0),
            end: Position::new(line as u32, current_indent.len() as u32)
        },
        new_text: indent
    })
}

#[derive(Clone)]
pub struct Backend {
    client: Client,
    document_state: Arc<RwLock<HashMap<Url, CurrentDocument>>>,
    opcodes: Arc<RwLock<HashMap<String, String>>>,
    json_reference_completion_list: Arc<RwLock<assets::CsoundJsonData>>,
    manual_temp_path: Arc<RwLock<PathBuf>>,
    plugins_opcodes: Arc<RwLock<HashMap<String, resolve_pulgins::CsoundPlugin>>>,
    queries: Arc<RwLock<parser::Queries>>,
    // manual and plugins are loaded in the background after `initialized`
    resources_ready: Arc<AtomicBool>
}

impl Backend {
    pub fn new(client: Client) -> Self {
        let queries = parser::load_queries();
        Self {
            client,
            document_state: Arc::new(RwLock::new(HashMap::new())),
            opcodes: Arc::new(RwLock::new(HashMap::new())),
            json_reference_completion_list: Arc::new(RwLock::new(assets::CsoundJsonData::default())),
            manual_temp_path: Arc::new(RwLock::new(PathBuf::new())),
            plugins_opcodes: Arc::new(RwLock::new(HashMap::new())),
            queries: Arc::new(RwLock::new(queries)),
            resources_ready: Arc::new(AtomicBool::new(false))
        }
    }
}

impl Backend {
    // Loads manual, opcode references and plugins into local maps, then swaps them in:
    // requests are never blocked by the downloads.
    async fn load_resources(&self) {
        let mut opcodes = HashMap::new();
        let mut manual_path = PathBuf::new();
        let mut cs_references = assets::CsoundJsonData::default();
        let mut plugins_opcodes = HashMap::new();

        let mut global_temp = std::env::temp_dir();
        global_temp.push(GLOBAL_TEMP_DIR);

        // Manual
        if let Err(e) = assets::load_manual_resources(&mut global_temp, &mut opcodes, &mut manual_path).await {
            self.client.log_message(
                MessageType::WARNING,
                format!("[WARNING] Csound manual unavailable: {}", e)
            ).await;
        }

        if let Err(e) = assets::read_csound_json_data(&mut cs_references,  &manual_path).await {
            self.client.log_message(
                MessageType::WARNING,
                format!("[WARNING] Csound opcodes references unavailable: {}", e)
            ).await;
        }

        // Plugins
        match resolve_pulgins::find_installed_plugins().await {
            Ok(plugs) => {
                let p_installed = plugs.iter().cloned().collect::<Vec<String>>().join(", ");
                self.client.log_message(MessageType::INFO, format!("[INFO] Installed plugins: {}", p_installed)).await;
                if !plugs.is_empty() {
                    if let Err(e) = resolve_pulgins::load_plugins_resources(&mut global_temp, &plugs, &mut plugins_opcodes).await {
                        self.client.log_message(MessageType::WARNING, format!("[WARNING] Impossible to load plugins: {}", e)).await;
                    } else {
                        let keys = &plugins_opcodes.keys().cloned().collect::<Vec<String>>().join(", ");
                        self.client.log_message(MessageType::INFO, format!("[INFO] Loaded plugins: {}", keys)).await;

                        // add plugins in cs_references for completion
                        if let Err(e) = resolve_pulgins::add_plugins_to_cs_references(&plugins_opcodes, &mut cs_references).await {
                            self.client.log_message(MessageType::WARNING, format!("[WARNING] Plugins opcodes: {}", e)).await;
                        }
                    };
                }
            },
            Err(e) => {
                self.client.log_message(MessageType::INFO, format!("[WARNING] Installed plugins: {}", e)).await;
            }
        };

        *self.opcodes.write().await = opcodes;
        *self.manual_temp_path.write().await = manual_path;
        *self.json_reference_completion_list.write().await = cs_references;
        *self.plugins_opcodes.write().await = plugins_opcodes;
        self.resources_ready.store(true, Ordering::SeqCst);
    }

    async fn analyze_open_documents(&self) {
        let uris: Vec<Url> = self.document_state.read().await.keys().cloned().collect();
        for uri in uris {
            self.analyze_document(uri).await;
        }
    }

    // Re-analyses a document after it has been (re)parsed and publishes its diagnostics.
    async fn analyze_document(&self, uri: Url) {
        let mut d = self.document_state.write().await;
        let opcodes = self.opcodes.read().await;
        let plugins = self.plugins_opcodes.read().await;
        let jr = self.json_reference_completion_list.read().await;

        // without the manual every opcode and flag would look unknown
        let resources_ready = self.resources_ready.load(Ordering::SeqCst);

        let mut diagnostics = Vec::new();
        let mut cached_diag: HashSet<(u32, u32, u32, u32, String)> = HashSet::new();
        if let Some(doc) = d.get_mut(&uri) {
            let text = doc.text.to_string();
            let nodes_to_diagnostics = parser::iterate_tree(&doc.tree, &text, &uri);
            doc.cached_typed_vars = nodes_to_diagnostics.typed_vars;
            doc.user_definitions = nodes_to_diagnostics.user_definitions;

            for (flag, flag_node) in nodes_to_diagnostics.flags.iter().filter(|_| resources_ready) {
                if let Some(ref flags) = jr.oflag_data {
                    let mut found = false;
                    'outer: for values in flags.values() {
                        let prex: Vec<&str> = values.prefix.split(',').collect();
                        for p in prex.iter() {
                            // "--env:NAME=VAL", "--devices[=in|out]", "-H#": keep only the flag name
                            let p = p.split(|c: char| matches!(c, '=' | ':' | '[' | '#') || c.is_whitespace())
                                .next()
                                .unwrap_or("")
                                .trim();

                            if p == *flag {
                                found = true;
                                break 'outer;
                            }
                        }
                    }

                    if !found {
                        let diag = utils::diagnostic_helper(
                            &flag_node, DiagnosticSeverity::ERROR, format!("Unknown flag type: <{}>", &flag), None
                        );
                        if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                            diagnostics.push(diag);
                        }
                    }
                }
            }

            // self.client.log_message(MessageType::INFO, format!("[INCLUDED UDO]: {:?}", nodes_to_diagnostics.included_udo_files)).await;
            for (ufile_path, ufile) in nodes_to_diagnostics.included_udo_files.iter() {
                let parsers = doc.internal_parsers.get_mut().unwrap_or_else(|e| e.into_inner());
                let entry = doc.cached_included_udo_files
                    .entry(ufile_path.clone())
                    .or_insert_with(|| ufile.clone());

                // the file is read again only when it changes on disk
                if entry.refresh() {
                    if let Err(e) = entry.iterate_included_udo_file(&mut parsers.csound_parser) {
                        self.client.log_message(MessageType::WARNING, format!("[WARNING]: {}", e)).await
                    }
                }
            }

            let ufile_to_remove = doc.cached_included_udo_files
                .keys()
                .filter(|k| !&nodes_to_diagnostics.included_udo_files.contains_key(*k))
                .cloned()
                .collect::<Vec<String>>();

            for p in ufile_to_remove { doc.cached_included_udo_files.remove(&p); }

            for var in &doc.user_definitions.unused_vars {
                if let Some(finded_node) = doc.tree.root_node()
                    .descendant_for_byte_range(var.node_location, var.node_location) {
                    let parent_finded_kind = finded_node
                        .parent()
                        .map(|p| p.kind())
                        .unwrap_or("");

                    #[cfg(debug_assertions)]
                    {
                        self.client.log_message(MessageType::INFO,
                            format!("UNUSED DEBUG: Kind='{}', parent={}, Text='{}', calls={}, scope={:?}",
                            finded_node.kind(),
                            parent_finded_kind,
                            var.var_name,
                            var.var_calls,
                            var.var_scope,
                        )).await;
                    }

                    let diag = utils::diagnostic_helper(
                        &finded_node, DiagnosticSeverity::HINT, utils::unused_message_from_kind(parent_finded_kind), Some(vec![DiagnosticTag::UNNECESSARY])
                    );

                    if !parser::is_diagnostic_cached(&diag, &mut cached_diag) { diagnostics.push(diag); }
                }
            }

            for var in &doc.user_definitions.undefined_vars {
                if let Some(finded_node) = doc.tree.root_node()
                    .descendant_for_byte_range(var.node_location, var.node_location) {
                    let parent_finded_kind = finded_node
                        .parent()
                        .map(|p| p.kind())
                        .unwrap_or("");

                    #[cfg(debug_assertions)]
                    {
                        self.client.log_message(MessageType::INFO,
                            format!("UNDEFINED DEBUG: Kind='{}', parent={}, Text='{}', calls={}, scope={:?}",
                            finded_node.kind(),
                            parent_finded_kind,
                            var.var_name,
                            var.var_calls,
                            var.var_scope
                        )).await;
                    }

                    for node_range in &var.references {
                        let mut pflag = false;
                        if parent_finded_kind == "macro_usage" {
                            pflag = doc.cached_included_udo_files
                                .values()
                                .any(|v| v.macro_list.contains(&var.var_name));
                        }

                        if !pflag {
                            let diag = Diagnostic {
                                range: *node_range,
                                severity: Some(DiagnosticSeverity::ERROR),
                                source: Some("csound-lsp".into()),
                                message: utils::undefined_message_from_kind(&parent_finded_kind),
                                ..Default::default()
                            };
                            if !parser::is_diagnostic_cached(&diag, &mut cached_diag) { diagnostics.push(diag); }
                        }
                    }
                }
            }
            // check arg types in xin and xout
            for udo in doc.user_definitions.user_defined_opcodes.values() {
                if !udo.is_valid || udo.udo_type == UdoType::Unknown {
                    continue;
                }

                let udo_node = &doc.tree.root_node().descendant_for_point_range(udo.node_position.0, udo.node_position.1);
                if let Some(n) = udo_node {
                    // check inputs
                    match udo.udo_type {
                        UdoType::Legacy => {
                            'xin_outer: for child_index in 0..n.child_count() {
                                let xin_node = n.child(child_index).and_then(|c| if c.kind() == "xin_statement" { Some(c) } else { None });
                                if let Some(xin_node) = xin_node {
                                    let mut arg_count = 0;
                                    for xin_child in xin_node.named_children(&mut xin_node.walk()) {
                                        if matches!(xin_child.kind(), "type_identifier_legacy" | "typed_identifier") {
                                            let vdata = parser::get_variable_data_type(xin_child, &text, &doc.user_definitions.user_defined_types);
                                            if let Some(vd) = vdata {
                                                if arg_count < udo.inputs.len() {
                                                    let source_type = &udo.inputs[arg_count].arg.data_type;
                                                    let source_shape = &udo.inputs[arg_count].arg.data_shape;
                                                    if vd.data_type != *source_type || vd.data_shape != *source_shape {
                                                        let diag = utils::diagnostic_helper(
                                                            &xin_child, DiagnosticSeverity::ERROR, format!("Positional argument type mismatch in udo signature. Should be: {:?} {:?}", source_type, source_shape), None
                                                        );

                                                        if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                                            diagnostics.push(diag);
                                                        }
                                                    }
                                                    if *source_type == VarDataType::Void {
                                                        break
                                                    }
                                                    arg_count += 1;
                                                } else {
                                                    let diag = utils::diagnostic_helper(
                                                        &xin_node, DiagnosticSeverity::ERROR, "Positional argument type mismatch in udo signature: too many arguments".to_string(), None
                                                    );

                                                    if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                                        diagnostics.push(diag);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if arg_count < udo.inputs.len() {
                                        let diag = utils::diagnostic_helper(
                                            &xin_node, DiagnosticSeverity::ERROR, "Positional argument type mismatch in udo signature: missing arguments".to_string(), None
                                        );

                                        if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                            diagnostics.push(diag);
                                        }
                                    }
                                    break 'xin_outer;
                                }
                            }
                        }
                        _ => { }
                    };
                }
                // TODO: check outputs
            }

            for node in nodes_to_diagnostics.opcodes.iter().filter(|_| resources_ready) {
                if let Some(nt) = parser::get_node_name(*node, &text) {
                    let node_type = nt.split_once(":").map(|(prefix, _)| prefix.to_string()).unwrap_or(nt.clone());
                    let is_included_udo = doc.cached_included_udo_files.values().any(|u| u.udo_list.contains(&node_type));

                    let is_in_completion = jr.opcodes_data.as_ref().map(|op| op.contains_key(&node_type)).unwrap_or(false);

                    if {
                        !nodes_to_diagnostics.udo.contains(&node_type) &&
                        !nodes_to_diagnostics.udt.contains(&node_type) &&
                        !plugins.contains_key(&node_type)              &&
                        !is_in_completion                              &&
                        !is_included_udo
                    } {
                        match opcodes.get(&node_type) {
                            Some(_) => { },
                            None => {
                                let diag = utils::diagnostic_helper(
                                    &node, DiagnosticSeverity::ERROR, format!("Unknown opcode: <{}>", node_type), None // also check if arg are corrects
                                );

                                if !parser::is_diagnostic_cached(&diag, &mut cached_diag) {
                                    diagnostics.push(diag);
                                }
                            }
                        }
                    }
                }
            }

            for node in nodes_to_diagnostics.types {
                let type_identifier = parser::get_node_name(node, &text).unwrap_or_default();
                let is_type_included = doc.cached_included_udo_files.values().any(|t| t.type_list.contains(&type_identifier));

                if !parser::is_valid_type(&type_identifier) && !nodes_to_diagnostics.udt.contains(&type_identifier) && !is_type_included {
                    let diag = utils::diagnostic_helper(
                        &node, DiagnosticSeverity::ERROR, format!("Unknown type identifier: <{}>", type_identifier), None
                    );

                    if !parser::is_diagnostic_cached(&diag, &mut cached_diag) { diagnostics.push(diag); }
                }
            }

            for node in nodes_to_diagnostics.generic_errors.iter() {
                let node_name = parser::get_node_name(node.node, &text).unwrap_or_default();
                let mut expand_error = false;
                let message = match node.error_type {
                    parser::GErrors::Syntax => {
                        format!("Syntax error: <{}>", node_name)
                    },
                    parser::GErrors::ExplicitType => {
                        format!("Unknown type identifier: <{}>", node_name)
                    },
                    parser::GErrors::ScoreStatement => {
                        "Unknown score statement syntax or missing mandatory p-fields".to_string()
                    },
                    parser::GErrors::MissingPfield => {
                        "Missing mandatory p-fields (p1, p2, p3)".to_string()
                    }
                    parser::GErrors::ControlLoopSyntaxError => {
                        expand_error = true;
                        "Unclosed control block".to_string()
                    },
                    parser::GErrors::InstrBlockSyntaxError => {
                        expand_error = true;
                        "Unclosed instr block".to_string()
                    },
                    parser::GErrors::UdoBlockSyntaxError => {
                        expand_error = true;
                        "Unclosed udo block".to_string()
                    },
                    parser::GErrors::CabbageBlockError=> {
                        expand_error = true;
                        "It is not possible to have a Cabbage and a Cabbage ARA block in the same .csd file".to_string()
                    },
                    parser::GErrors::UdoInputParamsError => {
                        format!("Invalid udo input types: <{}>", node_name)
                    },
                    parser::GErrors::UdoOutputsParamsError => {
                        format!("Invalid udo output types: <{}>", node_name)
                    },
                    parser::GErrors::Missing => {
                        let kind = node.node.kind();
                        if node.node.is_named() { format!("Missing {}", kind) } else { format!("Missing \"{}\"", kind) }
                    }
                };

                let diag = Diagnostic {
                    range: parser::get_node_range(&node.node, expand_error.then_some(&text)),
                    severity: Some(DiagnosticSeverity::ERROR),
                    source: Some("csound-lsp".into()),
                    message: message,
                    ..Default::default()
                };

                if !parser::is_diagnostic_cached(&diag, &mut cached_diag) { diagnostics.push(diag); }
            }

            for diag in diagnostics.iter_mut() {
                diag.range = utils::range_to_utf16(&doc.text, diag.range);
            }
        }
        self.client.publish_diagnostics(uri, diagnostics, None).await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::INCREMENTAL)),
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
            .log_message(MessageType::INFO, "[INFO] Csound LSP initialized!")
            .await;

        let backend = self.clone();
        tokio::spawn(async move {
            backend.load_resources().await;
            backend.client.log_message(MessageType::INFO, "[INFO] Csound resources loaded").await;
            backend.analyze_open_documents().await;
        });
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let doc = CurrentDocument::new(&params.text_document.text);
        self.document_state.write().await.insert(uri.clone(), doc);
        self.analyze_document(uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.document_state.write().await.remove(&uri);
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        {
            let mut d = self.document_state.write().await;
            if let Some(doc) = d.get_mut(&uri) {
                get_incremental_parsing(doc, &params.content_changes); // incremental parsing
            }
        }
        self.analyze_document(uri).await;
    }


    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri.clone();
        let pos = params.text_document_position_params.position;

        let dc = self.document_state.read().await;
        if let Some(doc) = dc.get(&uri) {
            if let Some(node) = parser::find_node_at_point(&doc.tree, utils::lsp_position_to_point(&doc.text, &pos)) {
                let node_kind = node.kind();
                let node_type = parser::get_node_name(node, &doc.text.to_string()).unwrap_or("".to_string()); // opcode key
                let opcodes = self.opcodes.read().await;
                let plugins = self.plugins_opcodes.read().await;

                #[cfg(debug_assertions)]
                {
                    let sib = node.prev_named_sibling().map(|p| p.kind()).unwrap_or("None");
                    self.client.log_message(MessageType::INFO,
                        format!("HOVER DEBUG: Kind='{}', Text='{}', Parent='{}', scope={:?}, sib={}",
                        node_kind,
                        node_type,
                        node.parent().map(|p| p.kind()).unwrap_or("None"),
                        parser::find_scope(node, &doc.text.to_string(), &doc.user_definitions.user_defined_types),
                        sib
                    )).await;
                }

                match node_kind {
                    "opcode_name" => {
                        if let Some(ud) = doc.user_definitions.user_defined_opcodes.get(&node_type.to_string()) {
                            let md = format!("## User-Defined Opcode\n```csound\n{}\n```", ud.signature);
                            // self.client.log_message(MessageType::INFO, format!("[INPUTS]: {:?}, [OUTPUTS]: {:?}", ud.inputs, ud.outputs)).await;
                            return Ok(Some(utils::hover_helper(md)))
                        }

                        for (_, udo_file) in doc.cached_included_udo_files.iter() {
                            if let Some(ud) = udo_file.user_defined_opcodes.get(&node_type.to_string()) {
                                let udo_source = udo_file.path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                                let md = format!("## User-Defined Opcode (from `{}`)\n```csound\n{}\n```", udo_source, ud.signature);
                                return Ok(Some(utils::hover_helper(md)))
                            }
                        }

                        if let Some(plug) = plugins.get(&node_type) {
                            let pdoc = format!("## Plugin Opcodes (from `{}`)\n{}", plug.libname, plug.documentation);
                            return Ok(Some(utils::hover_helper(pdoc)))
                        }

                        if let Some(reference) = opcodes.get(&node_type) {
                            return Ok(Some(utils::hover_helper(reference.clone())))
                        } else {
                            self.client.log_message(MessageType::WARNING,
                                format!("Manual not found for opcode <{}>", node_type)
                            ).await;
                        }
                    },
                    "identifier" => {
                        let is_type = node.parent()
                            .map(|p| p.kind() == "typed_identifier" || p.kind() == "type_identifier" || p.kind() == "typed_opcode_name")
                            .unwrap_or(false);

                        if is_type {
                            if let Some(child_type_name) = parser::get_node_name(node, &doc.text.to_string()) {
                                if let Some(sd) = doc.user_definitions.user_defined_types.get(&child_type_name) {
                                    let md = format!("## User-Defined Type\n```csound\n{}\n```", sd.udt_format);
                                    return Ok(Some(utils::hover_helper(md)))
                                }

                                for (_, udo_file) in doc.cached_included_udo_files.iter() {
                                    if let Some(sd) = udo_file.user_defined_types.get(&node_type.to_string()) {
                                        let udo_source = udo_file.path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                                        let md = format!("## User-Defined Type (from `{}`)\n```csound\n{}\n```", udo_source, sd.udt_format);
                                        return Ok(Some(utils::hover_helper(md)))
                                    }
                                }

                                let splitted_name = node_type.split_once(":").map(|(p, _)| p).unwrap_or(&node_type);
                                if let Some(reference) = opcodes.get(splitted_name) {
                                    return Ok(Some(utils::hover_helper(reference.clone())))
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
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;

        let dc = self.document_state.read().await;
        let Some(doc) = dc.get(uri) else { return Ok(None) };
        let jr = self.json_reference_completion_list.read().await;
        let text = doc.text.to_string();

        let sources = completion::CompletionSources {
            text: &text,
            tree: &doc.tree,
            uri,
            doc_type: &doc.doc_type,
            user_definitions: &doc.user_definitions,
            typed_vars: &doc.cached_typed_vars,
            included_udo_files: &doc.cached_included_udo_files,
            references: &jr
        };

        Ok(completion::complete(&sources, &pos, params.context.as_ref()).map(CompletionResponse::Array))
    }

    async fn semantic_tokens_full(&self, params: SemanticTokensParams) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;
        let dc = self.document_state.read().await;
        let queries = self.queries.read().await;
        if let Some(doc) = dc.get(&uri) {
            let text = doc.text.to_string();
            let mut st = parser::get_semantic_tokens(&queries.csound_highlights, &doc.tree, &text, None);
            let inj = {
                let mut parsers = doc.internal_parsers.lock().unwrap_or_else(|e| e.into_inner());
                let parsers = &mut *parsers;
                parser::get_injections(
                    &queries.csound_injection,
                    &doc.tree,
                    &text,
                    &mut parsers.csound_parser,
                    &queries.csound_highlights,
                    &mut parsers.py_parser,
                    &queries.py_highlights,
                    &mut parsers.html_parser,
                    &queries.html_highlights,
                    &mut parsers.json_parser,
                    &queries.json_highlights
                )
            };

            st.extend(inj);
            let stokens = parser::get_delta_pos(&mut st, &doc.text);

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

                if let Some(file_name) = file_paths.first().and_then(|p| Path::new(p).file_stem()) {
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
        let line = params.text_document_position.position.line as usize;

        let dc = self.document_state.read().await;
        let Some(doc) = dc.get(&uri) else { return Ok(None) };
        Ok(indent_edit(&doc.text, &doc.tree, line, &params.options).map(|edit| vec![edit]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(text: &str) -> CurrentDocument {
        CurrentDocument::new(text)
    }

    fn dump(node: tree_sitter::Node, out: &mut String) {
        out.push_str(&format!("{} {:?} {:?}-{:?}\n", node.kind(), node.byte_range(), node.start_position(), node.end_position()));
        for i in 0..node.child_count() {
            dump(node.child(i).unwrap(), out);
        }
    }

    fn change(start: (u32, u32), end: (u32, u32), text: &str) -> TextDocumentContentChangeEvent {
        TextDocumentContentChangeEvent {
            range: Some(Range::new(Position::new(start.0, start.1), Position::new(end.0, end.1))),
            range_length: None,
            text: text.to_string()
        }
    }

    #[test]
    fn incremental_edits_use_utf16_positions() {
        let mut doc = document("; \u{1F3B5} x\ninstr 1\n  kx = 1\nendin\n");
        // after the emoji: UTF-16 column 5 is char 4
        get_incremental_parsing(&mut doc, &vec![
            change((0, 5), (0, 6), "y\u{e8}"),
            change((2, 7), (2, 8), "22")
        ]);
        assert_eq!(doc.text.to_string(), "; \u{1F3B5} y\u{e8}\ninstr 1\n  kx = 22\nendin\n");

        let fresh = parser::parse_doc(&doc.text.to_string(), None);
        let (mut edited, mut expected) = (String::new(), String::new());
        dump(doc.tree.root_node(), &mut edited);
        dump(fresh.tree.root_node(), &mut expected);
        assert_eq!(edited, expected);
    }

    #[test]
    fn positions_past_the_end_of_a_line_are_clamped() {
        let text = Rope::from_str("ab\ncd\n");
        assert_eq!(utils::lsp_position_to_char(&text, &Position::new(0, 99)), 2);
        assert_eq!(utils::lsp_position_to_char(&text, &Position::new(9, 0)), 6);
        let point = utils::lsp_position_to_point(&Rope::from_str("; \u{1F3B5} x"), &Position::new(0, 5));
        assert_eq!(point.column, 7);
    }

    fn options(tab_size: u32, insert_spaces: bool) -> FormattingOptions {
        FormattingOptions { tab_size, insert_spaces, ..Default::default() }
    }

    #[test]
    fn indent_edit_replaces_the_current_indentation() {
        let doc = document("instr 1\nkx = 1\n     \nendin\n");
        let edit = indent_edit(&doc.text, &doc.tree, 1, &options(2, true)).unwrap();
        assert_eq!((edit.range.end.character, edit.new_text.as_str()), (0, "  "));

        let edit = indent_edit(&doc.text, &doc.tree, 1, &options(4, false)).unwrap();
        assert_eq!(edit.new_text, "\t");

        // the line break is not part of the indentation
        let edit = indent_edit(&doc.text, &doc.tree, 2, &options(2, true)).unwrap();
        assert_eq!(edit.range.end.character, 5);
    }

    #[test]
    fn indent_edit_works_on_lines_split_across_rope_chunks() {
        let body = "  kx = 1\n".repeat(400);
        let doc = document(&format!("instr 1\n{}endin\n", body));
        let line = (1..401)
            .find(|l| doc.text.line(*l).as_str().is_none())
            .expect("no line crosses a chunk boundary");

        let edit = indent_edit(&doc.text, &doc.tree, line, &options(4, true)).unwrap();
        assert_eq!((edit.range.end.character, edit.new_text.as_str()), (2, "    "));
    }
}
