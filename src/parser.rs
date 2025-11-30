use rust_embed::RustEmbed;
use tower_lsp::lsp_types::Position;
use tree_sitter::{ Node, Parser, Point, Tree };
use std::path::Path;
use std::collections::HashMap;
use tree_sitter_csound::LANGUAGE;

#[derive(RustEmbed)]
#[folder = "tree-sitter-csound/csound_manual/docs/opcodes"]
struct Asset;

pub fn parse_doc(text: &str) -> Tree {
    let mut p = Parser::new();
    let language = LANGUAGE.into();
    p.set_language(&language).unwrap();
    p.parse(text, None).unwrap()
}

pub fn find_node_at_position<'a>(tree: &'a Tree, pos: &Position) -> Option<Node<'a>> {
    let row = pos.line as usize;
    let col = pos.character as usize;

    tree.root_node().descendant_for_point_range(
        Point::new(row, col),
        Point::new(row, col),
    )
}

pub fn load_opcodes() -> HashMap<String, String> {
    let mut map = HashMap::new();

    for file_path in Asset::iter() {
        let file_name = file_path.as_ref();
        if file_name.ends_with(".md") {
            let name = Path::new(file_name)
                .file_stem().and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();

            if let Some(content_file) = Asset::get(file_name) {
                if let Ok(content_str) = std::str::from_utf8(content_file.data.as_ref()) {
                    map.insert(name, content_str.to_string());
                }
            }
        }
    }

    map
}
