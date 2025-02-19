#![allow(clippy::print_stdout)]
#![allow(clippy::large_enum_variant)]

use anyhow::bail;
use anyhow::Result;
use ark_core::coin_select::select_vtxos;
use ark_core::redeem;
use ark_core::redeem::create_and_sign_redeem_transaction;
use ark_core::round;
use ark_core::round::create_and_sign_forfeit_txs;
use ark_core::round::generate_nonce_tree;
use ark_core::round::sign_round_psbt;
use ark_core::round::sign_vtxo_tree;
use ark_core::server::RoundInput;
use ark_core::server::RoundOutput;
use ark_core::server::RoundStreamEvent;
use ark_core::server::VtxoOutPoint;
use ark_core::ArkAddress;
use ark_core::BoardingOutput;
use ark_core::DefaultVtxo;
use bitcoin::key::Keypair;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use clap::Parser;
use clap::Subcommand;
use futures::StreamExt;
use rand::thread_rng;
use serde::Deserialize;
use std::fs;
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "ark-sample")]
#[command(about = "An Ark client in your terminal")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "ark.config.toml")]
    config: String,

    /// Path to the seed file.
    #[arg(short, long, default_value = "ark.seed")]
    seed: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show the balance.
    Balance,
    /// Generate a boarding address.
    BoardingAddress,
    /// Generate an Ark address.
    OffchainAddress,
    /// Send coins to an Ark address.
    SendToArkAddress {
        /// Where to send the coins too.
        address: ArkAddressCli,
        /// How many sats to send.
        amount: u64,
    },
    /// Transform boarding outputs and VTXOs into fresh, confirmed VTXOs.
    Settle,
}

#[derive(Clone)]
struct ArkAddressCli(ArkAddress);

impl FromStr for ArkAddressCli {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = ArkAddress::decode(s)?;

        Ok(Self(address))
    }
}

#[derive(Deserialize)]
struct Config {
    ark_server_url: String,
    esplora_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    let seed = fs::read_to_string(cli.seed)?;
    let sk = SecretKey::from_str(&seed)?;

    let config = fs::read_to_string(cli.config)?;
    let config: Config = toml::from_str(&config)?;

    let secp = Secp256k1::new();

    let pk = PublicKey::from_secret_key(&secp, &sk);

    let ark_server_url = config.ark_server_url;
    let mut grpc_client = ark_grpc::Client::new(ark_server_url);

    grpc_client.connect().await?;

    let server_info = grpc_client.get_info().await?;

    let esplora_client = EsploraClient::new(&config.esplora_url)?;

    // In this example we use the same script for all VTXOs.
    let default_vtxo = DefaultVtxo::new(
        &secp,
        server_info.pk.x_only_public_key().0,
        pk.x_only_public_key().0,
        server_info.unilateral_exit_delay,
        server_info.network,
    );

    // In this example we use the same script for all boarding outputs.
    let boarding_output = BoardingOutput::new(
        &secp,
        server_info.pk.x_only_public_key().0,
        pk.x_only_public_key().0,
        &server_info.boarding_descriptor_template,
        server_info.unilateral_exit_delay,
        server_info.network,
    );

    match &cli.command {
        Commands::Balance => {
            let vtxos = list_vtxos(&grpc_client, &esplora_client, &[default_vtxo]).await?;
            let boarding_outputs =
                list_boarding_outputs(&esplora_client, &[boarding_output]).await?;

            println!(
                "Offchain balance: spendable = {}, expired = {}",
                vtxos.spendable_balance(),
                vtxos.expired_balance()
            );
            println!(
                "Boarding balance: spendable = {}, expired = {}, pending = {}",
                boarding_outputs.spendable_balance(),
                boarding_outputs.expired_balance(),
                boarding_outputs.pending_balance()
            );
        }
        Commands::BoardingAddress => {
            let boarding_address = boarding_output.address();

            println!("Send coins to this on-chain address: {boarding_address}\n");
            println!(
                "Once confirmed, you will have {} seconds to exchange the boarding output for a VTXO.",
                boarding_output.exit_delay_duration().as_secs()
            );
        }
        Commands::OffchainAddress => {
            let offchain_address = default_vtxo.to_ark_address();

            println!("Send VTXOs to this offchain address: {offchain_address}\n");
        }
        Commands::SendToArkAddress { address, amount } => {
            let amount = Amount::from_sat(*amount);

            let vtxos = list_vtxos(&grpc_client, &esplora_client, &[default_vtxo.clone()]).await?;

            let vtxo_outpoints = vtxos
                .spendable
                .iter()
                .map(|(outpoint, _)| ark_core::coin_select::VtxoOutPoint {
                    outpoint: outpoint.outpoint.expect("outpoint"),
                    expire_at: outpoint.expire_at,
                    amount: outpoint.amount,
                })
                .collect::<Vec<_>>();

            let selected_outpoints = select_vtxos(vtxo_outpoints, amount, server_info.dust, true)?;

            let vtxo_inputs = vtxos
                .spendable
                .into_iter()
                .filter(|(outpoint, _)| {
                    selected_outpoints
                        .iter()
                        .any(|o| Some(o.outpoint) == outpoint.outpoint)
                })
                .map(|(outpoint, vtxo)| {
                    redeem::VtxoInput::new(
                        vtxo,
                        outpoint.amount,
                        outpoint.outpoint.expect("outpoint"),
                    )
                })
                .collect::<Vec<_>>();

            let change_address = default_vtxo.to_ark_address();

            let secp = Secp256k1::new();
            let kp = Keypair::from_secret_key(&secp, &sk);

            let signed_redeem_psbt = create_and_sign_redeem_transaction(
                &kp,
                &address.0,
                amount,
                &change_address,
                &vtxo_inputs,
            )?;

            let psbt = grpc_client
                .submit_redeem_transaction(signed_redeem_psbt.clone())
                .await?;

            let txid = psbt.extract_tx()?.compute_txid();

            println!("Sent {amount} to {} in transaction {txid}", address.0);
        }
        Commands::Settle => {
            let vtxos = list_vtxos(&grpc_client, &esplora_client, &[default_vtxo.clone()]).await?;
            let boarding_outputs =
                list_boarding_outputs(&esplora_client, &[boarding_output]).await?;

            let res = settle(
                &grpc_client,
                &server_info,
                sk,
                vtxos,
                boarding_outputs,
                default_vtxo.to_ark_address(),
            )
            .await;

            match res {
                Ok(Some(txid)) => {
                    println!(
                        "Settled boarding outputs and VTXOs into new VTXOs.\n\n Round TXID: {txid}\n"
                    );
                }
                Ok(None) => {
                    println!("No boarding outputs or VTXOs can be settled at the moment.");
                }
                Err(e) => {
                    println!("Failed to settle boarding outputs and VTXOs: {e:#}");
                }
            }
        }
    }

    Ok(())
}

struct Vtxos {
    /// VTXOs that can be spent in collaboration with the Ark server.
    spendable: Vec<(VtxoOutPoint, DefaultVtxo)>,
    /// VTXOs that should only be spent unilaterally.
    expired: Vec<(VtxoOutPoint, DefaultVtxo)>,
}

impl Vtxos {
    fn spendable_balance(&self) -> Amount {
        self.spendable
            .iter()
            .fold(Amount::ZERO, |acc, x| acc + x.0.amount)
    }

    fn expired_balance(&self) -> Amount {
        self.expired
            .iter()
            .fold(Amount::ZERO, |acc, x| acc + x.0.amount)
    }
}

async fn list_vtxos(
    grpc_client: &ark_grpc::Client,
    onchain_explorer: &EsploraClient,
    vtxos: &[DefaultVtxo],
) -> Result<Vtxos> {
    let mut spendable = Vec::new();
    let mut expired = Vec::new();
    for vtxo in vtxos.iter() {
        // The VTXOs for the given Ark address that the Ark server tells us about.
        let vtxo_outpoints = grpc_client.list_vtxos(&vtxo.to_ark_address()).await?;

        // We look to see if we can find any on-chain VTXOs for this address.
        let onchain_vtxos = onchain_explorer.find_outpoints(vtxo.address()).await?;

        for vtxo_outpoint in vtxo_outpoints.spendable {
            if let Some(outpoint) = vtxo_outpoint.outpoint {
                let now = std::time::UNIX_EPOCH.elapsed()?;
                match onchain_vtxos
                    .iter()
                    .find(|onchain_utxo| onchain_utxo.outpoint == outpoint)
                {
                    // VTXOs that have been confirmed on the blockchain, but whose
                    // exit path is now _active_, have expired.
                    Some(ExplorerUtxo {
                        confirmation_blocktime: Some(confirmation_blocktime),
                        ..
                    }) if vtxo.can_be_claimed_unilaterally_by_owner(
                        now,
                        Duration::from_secs(*confirmation_blocktime),
                    ) =>
                    {
                        expired.push((vtxo_outpoint, vtxo.clone()));
                    }
                    // All other VTXOs (either still offchain or on-chain but with an inactive exit
                    // path) are spendable.
                    _ => {
                        spendable.push((vtxo_outpoint, vtxo.clone()));
                    }
                }
            }
        }
    }

    Ok(Vtxos { spendable, expired })
}

struct BoardingOutputs {
    /// Boarding outputs that can be converted into VTXOs in collaboration with the Ark server.
    spendable: Vec<(OutPoint, Amount, BoardingOutput)>,
    /// Boarding outputs that should only be spent unilaterally.
    expired: Vec<(OutPoint, Amount, BoardingOutput)>,
    /// Boarding outputs that are not yet confirmed on-chain.
    pending: Vec<(OutPoint, Amount, BoardingOutput)>,
}

impl BoardingOutputs {
    fn spendable_balance(&self) -> Amount {
        self.spendable.iter().fold(Amount::ZERO, |acc, x| acc + x.1)
    }

    fn expired_balance(&self) -> Amount {
        self.expired.iter().fold(Amount::ZERO, |acc, x| acc + x.1)
    }

    fn pending_balance(&self) -> Amount {
        self.pending.iter().fold(Amount::ZERO, |acc, x| acc + x.1)
    }
}

async fn list_boarding_outputs(
    onchain_explorer: &EsploraClient,
    boarding_outputs: &[BoardingOutput],
) -> Result<BoardingOutputs> {
    let mut spendable = Vec::new();
    let mut expired = Vec::new();
    let mut pending = Vec::new();
    for boarding_output in boarding_outputs.iter() {
        let boarding_address = boarding_output.address();

        // The boarding outputs corresponding to this address that we can find on-chain.
        let boarding_utxos = onchain_explorer.find_outpoints(boarding_address).await?;

        for boarding_utxo in boarding_utxos.iter() {
            match *boarding_utxo {
                // The boarding output can be found on-chain.
                ExplorerUtxo {
                    confirmation_blocktime: Some(confirmation_blocktime),
                    outpoint,
                    amount,
                } => {
                    let now = std::time::UNIX_EPOCH.elapsed()?;

                    // If the boarding output is on-chain can be spent unilaterally, it has expired.
                    if boarding_output.can_be_claimed_unilaterally_by_owner(
                        now,
                        Duration::from_secs(confirmation_blocktime),
                    ) {
                        expired.push((outpoint, amount, boarding_output.clone()));
                    }
                    // If the boarding output is on-chain and cannot be spent unilaterally, it is
                    // spendable.
                    else {
                        spendable.push((outpoint, amount, boarding_output.clone()));
                    }
                }
                // The boarding output is still pending confirmation.
                ExplorerUtxo {
                    confirmation_blocktime: None,
                    outpoint,
                    amount,
                } => {
                    pending.push((outpoint, amount, boarding_output.clone()));
                }
            }
        }
    }

    Ok(BoardingOutputs {
        spendable,
        expired,
        pending,
    })
}

async fn settle(
    grpc_client: &ark_grpc::Client,
    server_info: &ark_core::server::Info,
    sk: SecretKey,
    vtxos: Vtxos,
    boarding_outputs: BoardingOutputs,
    to_address: ArkAddress,
) -> Result<Option<Txid>> {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    if vtxos.spendable.is_empty() && boarding_outputs.spendable.is_empty() {
        return Ok(None);
    }

    let ephemeral_kp = Keypair::new(&secp, &mut rng);

    let round_inputs = {
        let boarding_inputs = boarding_outputs
            .spendable
            .clone()
            .into_iter()
            .map(|o| RoundInput::new(Some(o.0), o.2.tapscripts()));

        let vtxo_inputs = vtxos
            .spendable
            .clone()
            .into_iter()
            .map(|v| RoundInput::new(v.0.outpoint, v.1.tapscripts()));

        boarding_inputs.chain(vtxo_inputs).collect::<Vec<_>>()
    };

    let payment_id = grpc_client
        .register_inputs_for_next_round(ephemeral_kp.public_key(), &round_inputs)
        .await?;

    tracing::info!(
        payment_id,
        n_round_inputs = round_inputs.len(),
        "Registered round inputs"
    );

    let spendable_amount = boarding_outputs.spendable_balance() + vtxos.spendable_balance();

    let round_outputs = vec![RoundOutput::new_virtual(to_address, spendable_amount)];
    grpc_client
        .register_outputs_for_next_round(payment_id.clone(), &round_outputs)
        .await?;

    tracing::info!(
        n_round_outputs = round_outputs.len(),
        "Registered round outputs"
    );

    // We must ping once. TODO: Is that enough?
    grpc_client.ping(payment_id).await?;

    let mut event_stream = grpc_client.get_event_stream().await?;

    let round_signing_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundSigning(e))) => e,
        other => bail!("Did not get round signing event: {other:?}"),
    };

    let round_id = round_signing_event.id;

    tracing::info!(round_id, "Round signing started");

    let unsigned_vtxo_tree = round_signing_event
        .unsigned_vtxo_tree
        .expect("to have an unsigned VTXO tree");

    let nonce_tree = generate_nonce_tree(&mut rng, &unsigned_vtxo_tree, ephemeral_kp.public_key())?;

    grpc_client
        .submit_tree_nonces(
            round_id,
            ephemeral_kp.public_key(),
            nonce_tree.to_pub_nonce_tree().into_inner(),
        )
        .await?;

    let round_signing_nonces_generated_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundSigningNoncesGenerated(e))) => e,
        other => bail!("Did not get round signing nonces generated event: {other:?}"),
    };

    let round_id = round_signing_nonces_generated_event.id;

    let agg_pub_nonce_tree = round_signing_nonces_generated_event.tree_nonces;

    tracing::info!(round_id, "Round combined nonces generated");

    let partial_sig_tree = sign_vtxo_tree(
        server_info.round_lifetime,
        server_info.pk.x_only_public_key().0,
        &ephemeral_kp,
        &unsigned_vtxo_tree,
        &round_signing_event.unsigned_round_tx,
        round_signing_event.cosigners_pubkeys,
        nonce_tree,
        agg_pub_nonce_tree.into(),
    )?;

    grpc_client
        .submit_tree_signatures(
            round_id,
            ephemeral_kp.public_key(),
            partial_sig_tree.into_inner(),
        )
        .await?;

    let round_finalization_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundFinalization(e))) => e,
        other => bail!("Did not get round finalization event: {other:?}"),
    };

    let round_id = round_finalization_event.id;

    tracing::info!(round_id, "Round finalization started");

    let vtxo_inputs = vtxos
        .spendable
        .into_iter()
        .map(|(outpoint, vtxo)| {
            round::VtxoInput::new(
                vtxo,
                outpoint.amount,
                outpoint.outpoint.expect("VTXO outpoint"),
            )
        })
        .collect::<Vec<_>>();

    let keypair = Keypair::from_secret_key(&secp, &sk);
    let signed_forfeit_psbts = create_and_sign_forfeit_txs(
        &keypair,
        vtxo_inputs.as_slice(),
        round_finalization_event.connectors,
        round_finalization_event.min_relay_fee_rate,
        &server_info.forfeit_address,
        server_info.dust,
    )?;

    let mut round_psbt = round_finalization_event.round_tx;

    let sign_for_pk_fn = |_: &XOnlyPublicKey,
                          msg: &secp256k1::Message|
     -> Result<schnorr::Signature, ark_core::Error> {
        Ok(secp.sign_schnorr_no_aux_rand(msg, &keypair))
    };

    let onchain_inputs = boarding_outputs
        .spendable
        .into_iter()
        .map(|(outpoint, _, boarding_output)| round::OnChainInput::new(boarding_output, outpoint))
        .collect::<Vec<_>>();

    sign_round_psbt(sign_for_pk_fn, &mut round_psbt, &onchain_inputs)?;

    grpc_client
        .submit_signed_forfeit_txs(signed_forfeit_psbts, round_psbt)
        .await?;

    let round_finalized_event = match event_stream.next().await {
        Some(Ok(RoundStreamEvent::RoundFinalized(e))) => e,
        other => bail!("Did not get round finalized event: {other:?}"),
    };

    let round_id = round_finalized_event.id;

    tracing::info!(round_id, "Round finalized");

    Ok(Some(round_finalized_event.round_txid))
}

pub struct EsploraClient {
    esplora_client: esplora_client::AsyncClient,
}

#[derive(Clone, Copy, Debug)]
pub struct ExplorerUtxo {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub confirmation_blocktime: Option<u64>,
}

impl EsploraClient {
    pub fn new(url: &str) -> Result<Self> {
        // TODO: Move to config file.
        let builder = esplora_client::Builder::new(url);
        let esplora_client = builder.build_async()?;

        Ok(Self { esplora_client })
    }

    async fn find_outpoints(&self, address: &bitcoin::Address) -> Result<Vec<ExplorerUtxo>> {
        let script_pubkey = address.script_pubkey();
        let txs = self
            .esplora_client
            .scripthash_txs(&script_pubkey, None)
            .await?;

        let outputs = txs
            .into_iter()
            .flat_map(|tx| {
                let txid = tx.txid;
                tx.vout
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.scriptpubkey == script_pubkey)
                    .map(|(i, v)| ExplorerUtxo {
                        outpoint: OutPoint {
                            txid,
                            vout: i as u32,
                        },
                        amount: Amount::from_sat(v.value),
                        confirmation_blocktime: tx.status.block_time,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut utxos = Vec::new();
        for output in outputs.iter() {
            let outpoint = output.outpoint;
            let status = self
                .esplora_client
                .get_output_status(&outpoint.txid, outpoint.vout as u64)
                .await?;

            match status {
                Some(esplora_client::OutputStatus { spent: false, .. }) | None => {
                    utxos.push(*output);
                }
                // Ignore spent transaction outputs
                Some(esplora_client::OutputStatus { spent: true, .. }) => {}
            }
        }

        Ok(utxos)
    }
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            "debug,\
             tower=info,\
             hyper_util=info,\
             hyper=info,\
             h2=warn,\
             reqwest=info,\
             ark_core=info",
        )
        .init()
}
