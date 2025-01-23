#![allow(clippy::unwrap_used)]

use ark_rs::wallet::BoardingWallet;
use ark_rs::wallet::OnchainWallet;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Amount;
use common::init_tracing;
use common::set_up_client;
use common::Nigiri;
use rand::thread_rng;
use std::sync::Arc;

mod common;

#[tokio::test]
#[ignore]
pub async fn e2e() {
    init_tracing();
    let nigiri = Arc::new(Nigiri::default());

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

    let alice_boarding_output = {
        let alice_asp_info = alice.asp_info.clone();
        let asp_pk = alice_asp_info.pk;
        let (asp_pk, _) = asp_pk.inner.x_only_public_key();

        alice_wallet
            .new_boarding_output(
                asp_pk,
                alice_asp_info.round_lifetime,
                &alice_asp_info.boarding_descriptor_template,
                alice_asp_info.network,
            )
            .unwrap()
    };

    let boarding_output = nigiri
        .faucet_fund(alice_boarding_output.address(), Amount::ONE_BTC)
        .await;

    tracing::debug!("Boarding output: {boarding_output:?}");

    let offchain_balance = alice.offchain_balance().await.unwrap();

    tracing::debug!("Pre boarding: Alice offchain balance: {offchain_balance}");

    alice.board(&mut rng).await.unwrap();

    let offchain_balance = alice.offchain_balance().await.unwrap();
    tracing::debug!("Post boarding: Alice offchain balance: {offchain_balance}");

    let bob_key = SecretKey::new(&mut rng);
    let bob_keypair = Keypair::from_secret_key(&secp, &bob_key);

    let (bob, _bob_wallet) =
        set_up_client("bob".to_string(), bob_keypair, nigiri.clone(), secp).await;

    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let bob_vtxos = bob.list_vtxos().await.unwrap();
    tracing::debug!(
        ?bob_vtxos,
        "Pre payment: Bob offchain balance: {bob_offchain_balance}"
    );

    let (bob_offchain_address, _) = bob.get_offchain_address();
    let amount = Amount::from_sat(100_000);
    tracing::debug!("Alice is sending {amount} to Bob offchain...");

    alice.send_vtxo(bob_offchain_address, amount).await.unwrap();

    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let bob_vtxos = bob.list_vtxos().await.unwrap();
    tracing::debug!(
        ?bob_vtxos,
        "Post payment: Bob offchain balance: {bob_offchain_balance}"
    );

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    tracing::debug!("Post payment: Alice offchain balance: {alice_offchain_balance}");

    bob.board(&mut rng).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let bob_offchain_balance = bob.offchain_balance().await.unwrap();
    let bob_vtxos = bob.list_vtxos().await.unwrap();
    tracing::debug!(
        ?bob_vtxos,
        "Post settlement: Bob offchain balance: {bob_offchain_balance}"
    );

    let onchain_address = alice_wallet.get_onchain_address().unwrap();

    alice_wallet.sync().await.unwrap();
    let balance = alice_wallet.balance().unwrap();

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let alice_vtxos = alice.list_vtxos().await.unwrap();
    tracing::debug!(
        ?alice_vtxos,
        "Pre off-boarding: Alice offchain balance: {alice_offchain_balance}"
    );
    tracing::debug!(?balance, "Pre off-boarding: Alice onchain balance");
    let txid = alice
        .off_board(&mut rng, onchain_address, Amount::ONE_BTC / 5)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    alice_wallet.sync().await.unwrap();
    let balance = alice_wallet.balance().unwrap();

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let alice_vtxos = alice.list_vtxos().await.unwrap();
    tracing::debug!(
        %txid,
        ?alice_vtxos,
        "Post off-boarding: Alice offchain balance: {alice_offchain_balance}"
    );
    tracing::debug!(?balance, "Post off-boarding: Alice onchain balance");

    tracing::debug!(
        ?alice_vtxos,
        "Pre unilateral off-boarding: Alice offchain balance: {alice_offchain_balance}"
    );

    alice.commit_vtxos_on_chain().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    let alice_vtxos = alice.list_vtxos().await.unwrap();

    tracing::debug!(
        ?alice_vtxos,
        "Post unilateral off-boarding: Alice offchain balance: {alice_offchain_balance}"
    );

    // If you set the ASP's `ARK_UNILATERAL_EXIT_DELAY` to the minimum value of 512 and you wait
    // long enough here, the VTXO will disappear from the list of VTXOs, as it will have
    // "become" a regular UTXO.

    // nigiri.mine(1).await;

    // tracing::info!("Waiting 512 seconds to make VTXO spendable");
    // tokio::time::sleep(std::time::Duration::from_secs(512)).await;

    // tracing::info!("VTXO should be spendable now");
}
