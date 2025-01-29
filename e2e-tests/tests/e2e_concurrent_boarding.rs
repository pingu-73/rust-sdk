#![allow(clippy::unwrap_used)]

use ark_bdk_wallet::Wallet;
use ark_core::BoardingOutput;
use ark_rs::wallet::BoardingWallet;
use ark_rs::Client;
use bitcoin::key::Secp256k1;
use bitcoin::Amount;
use common::init_tracing;
use common::set_up_client;
use common::InMemoryDb;
use common::Nigiri;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::borrow::Borrow;
use std::sync::Arc;
use tokio::try_join;

mod common;

#[tokio::test]
#[ignore]
pub async fn concurrent_boarding() {
    init_tracing();
    let nigiri = Arc::new(Nigiri::default());

    let secp = Secp256k1::new();

    let (alice, alice_wallet) =
        set_up_client("alice".to_string(), nigiri.clone(), secp.clone()).await;

    let (bob, bob_wallet) = set_up_client("bob".to_string(), nigiri.clone(), secp.clone()).await;

    let (claire, claire_wallet) =
        set_up_client("claire".to_string(), nigiri.clone(), secp.clone()).await;

    let alice_boarding_output = new_boarding_output(&alice, alice_wallet).await;
    let bob_boarding_output = new_boarding_output(&bob, bob_wallet).await;
    let claire_boarding_output = new_boarding_output(&claire, claire_wallet).await;

    let alice_initial_balance = Amount::ONE_BTC;
    let alice_boarding_output = nigiri
        .faucet_fund(alice_boarding_output.address(), alice_initial_balance)
        .await;

    let bob_initial_balance = Amount::ONE_BTC;
    let bob_boarding_output = nigiri
        .faucet_fund(bob_boarding_output.address(), bob_initial_balance)
        .await;

    let claire_initial_balance = Amount::ONE_BTC;
    let claire_boarding_output = nigiri
        .faucet_fund(claire_boarding_output.address(), claire_initial_balance)
        .await;

    tracing::debug!("Boarding output alice: {alice_boarding_output:?}");
    tracing::debug!("Boarding output bob: {bob_boarding_output:?}");
    tracing::debug!("Boarding output claire: {claire_boarding_output:?}");

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let claire_offchain_balance = claire.offchain_balance().await.unwrap();
    tracing::debug!("Pre boarding: Alice offchain balance: {alice_offchain_balance:?}");
    tracing::debug!("Pre boarding: Bob offchain balance: {bob_offchain_balance:?}");
    tracing::debug!("Pre boarding: Claire offchain balance: {claire_offchain_balance:?}");

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
    tracing::debug!("Post boarding: Alice offchain balance: {alice_offchain_balance:?}");
    tracing::debug!("Post boarding: Bob offchain balance: {bob_offchain_balance:?}");
    tracing::debug!("Post boarding: Claire offchain balance: {claire_offchain_balance:?}");

    let (bob_offchain_address, _) = bob.get_offchain_address();
    let amount = Amount::from_sat(100_000);

    bob.list_vtxos().await.unwrap();

    let alice_task = tokio::spawn(async move {
        tracing::debug!("Alice is sending {amount} to Bob offchain...");
        alice.send_vtxo(bob_offchain_address, amount).await.unwrap();
        alice
    });
    let claire_task = tokio::spawn(async move {
        tracing::debug!("Claire is sending {amount} to Bob offchain...");
        claire
            .send_vtxo(bob_offchain_address, amount)
            .await
            .unwrap();
        claire
    });

    let (_alice, _claire) = try_join!(alice_task, claire_task).unwrap();

    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let bob_vtxos = bob.list_vtxos().await.unwrap();
    tracing::debug!(
        ?bob_vtxos,
        "Post payment: Bob offchain balance: {bob_offchain_balance:?}"
    );

    assert_eq!(
        bob_offchain_balance.total(),
        bob_initial_balance + amount * 2
    );
}

async fn new_boarding_output(
    client: &Client<Nigiri, Wallet<InMemoryDb>>,
    wallet: impl Borrow<Wallet<InMemoryDb>>,
) -> BoardingOutput {
    let asp_info = client.asp_info.clone();
    let asp_pk = asp_info.pk;
    let (asp_pk, _) = asp_pk.inner.x_only_public_key();

    wallet
        .borrow()
        .new_boarding_output(
            asp_pk,
            asp_info.round_lifetime,
            &asp_info.boarding_descriptor_template,
            asp_info.network,
        )
        .unwrap()
}
