#![allow(clippy::unwrap_used)]

use ark_bdk_wallet::Wallet;
use ark_rs::boarding_output::BoardingOutput;
use ark_rs::wallet::BoardingWallet;
use ark_rs::Client;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Amount;
use common::init_tracing;
use common::set_up_client;
use common::InMemoryDb;
use common::Nigiri;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::SeedableRng;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::try_join;

mod common;

#[tokio::test]
pub async fn multi_party_e2e() {
    init_tracing();
    let nigiri = Arc::new(Nigiri::new());

    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let alice_key = SecretKey::new(&mut rng);
    let alice_keypair = Keypair::from_secret_key(&secp, &alice_key);
    let (alice, alice_wallet) = set_up_client(
        "alice".to_string(),
        alice_keypair,
        nigiri.clone(),
        secp.clone(),
    )
    .await;

    let bob_key = SecretKey::new(&mut rng);
    let bob_keypair = Keypair::from_secret_key(&secp, &bob_key);
    let (bob, bob_wallet) =
        set_up_client("bob".to_string(), bob_keypair, nigiri.clone(), secp.clone()).await;

    let claire_key = SecretKey::new(&mut rng);
    let claire_keypair = Keypair::from_secret_key(&secp, &claire_key);
    let (claire, claire_wallet) = set_up_client(
        "claire".to_string(),
        claire_keypair,
        nigiri.clone(),
        secp.clone(),
    )
    .await;

    let alice_boarding_address = new_boarding_address(&alice, &alice_wallet).await;
    let bob_boarding_address = new_boarding_address(&bob, &bob_wallet).await;
    let claire_boarding_address = new_boarding_address(&claire, &claire_wallet).await;

    let alice_boarding_output = nigiri
        .faucet_fund(alice_boarding_address.address(), Amount::ONE_BTC)
        .await;

    let bob_initial_balance = Amount::ONE_BTC;
    let bob_boarding_output = nigiri
        .faucet_fund(bob_boarding_address.address(), bob_initial_balance)
        .await;
    let claire_boarding_output = nigiri
        .faucet_fund(claire_boarding_address.address(), Amount::ONE_BTC)
        .await;

    tracing::debug!("Boarding output alice: {alice_boarding_output:?}");
    tracing::debug!("Boarding output bob: {bob_boarding_output:?}");
    tracing::debug!("Boarding output claire: {claire_boarding_output:?}");

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let claire_offchain_balance = claire.offchain_balance().await.unwrap();
    tracing::debug!("Pre boarding: Alice offchain balance: {alice_offchain_balance}");
    tracing::debug!("Pre boarding: Bob offchain balance: {bob_offchain_balance}");
    tracing::debug!("Pre boarding: Claire offchain balance: {claire_offchain_balance}");

    let alice_task = tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        alice.board(&mut rng).await.unwrap();
        alice
    });

    let bob_task = tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        bob.board(&mut rng).await.unwrap();
        bob
    });

    let claire_task = tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        claire.board(&mut rng).await.unwrap();
        claire
    });

    let (alice, bob, claire) = try_join!(alice_task, bob_task, claire_task).unwrap();

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let claire_offchain_balance = claire.offchain_balance().await.unwrap();
    tracing::debug!("Post boarding: Alice offchain balance: {alice_offchain_balance}");
    tracing::debug!("Post boarding: Bob offchain balance: {bob_offchain_balance}");
    tracing::debug!("Post boarding: Claire offchain balance: {claire_offchain_balance}");

    let (bob_offchain_address, _) = bob.get_offchain_address();
    let amount = Amount::from_sat(100_000);

    bob.list_vtxos().await.unwrap();

    let alice_task = tokio::spawn(async move {
        tracing::debug!("Alice is sending {amount} to Bob offchain...");
        alice.send_oor(bob_offchain_address, amount).await.unwrap();
        alice
    });
    let claire_task = tokio::spawn(async move {
        tracing::debug!("Claire is sending {amount} to Bob offchain...");
        claire.send_oor(bob_offchain_address, amount).await.unwrap();
        claire
    });

    let (_alice, _claire) = try_join!(alice_task, claire_task).unwrap();

    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let bob_vtxos = bob.list_vtxos().await.unwrap();
    tracing::debug!(
        ?bob_vtxos,
        "Post payment: Bob offchain balance: {bob_offchain_balance}"
    );

    assert_eq!(bob_offchain_balance, bob_initial_balance + amount * 2);
}

async fn new_boarding_address(
    client: &Client<Nigiri, Wallet<InMemoryDb>>,
    alice_wallet: &Arc<Mutex<Wallet<InMemoryDb>>>,
) -> BoardingOutput {
    let alice_asp_info = client.asp_info.clone();
    let asp_pk = alice_asp_info.pk;
    let (asp_pk, _) = asp_pk.inner.x_only_public_key();

    let mut wallet = alice_wallet.lock().await;
    wallet
        .new_boarding_address(
            asp_pk,
            alice_asp_info.round_lifetime,
            &alice_asp_info.boarding_descriptor_template,
            alice_asp_info.network,
        )
        .unwrap()
}
