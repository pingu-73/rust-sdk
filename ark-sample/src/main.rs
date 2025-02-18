#![allow(clippy::unwrap_used)]

use ark_rest::Client;

#[tokio::main]
async fn main() {
    let ark_server_url = "http://localhost:7070".to_string();
    let client = Client::new(ark_server_url);

    let _info = client.get_info().await.unwrap();
}
