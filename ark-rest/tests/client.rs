use ark_rest::Client;

#[tokio::test]
#[ignore]
async fn can_get_info_from_ark_server() {
    let client = Client::new("http://localhost:7070".to_string());
    let res = client.get_info().await;

    assert!(res.is_ok())
}
