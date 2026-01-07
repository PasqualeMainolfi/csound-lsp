mod server;
mod parser;
mod utils;
mod assets;
mod resolve_udos;
mod resolve_pulgins;

use tower_lsp::{ LspService, Server };
use server::Backend;


#[tokio::main]
async fn main() {
    let (service, socket) = LspService::new(|client| Backend::new(client));
    Server::new(tokio::io::stdin(), tokio::io::stdout(), socket)
        .serve(service)
        .await;
}
