pub mod coin_select;
pub mod default_vtxo;
pub mod redeem;
pub mod round;
pub mod server;
pub mod tx_weight_estimator;
pub mod unilateral_exit;

mod ark_address;
mod boarding_output;
mod conversions;
mod error;
mod forfeit_fee;
mod history;
mod internal_node;
mod script;

pub use ark_address::ArkAddress;
pub use boarding_output::BoardingOutput;
pub use default_vtxo::DefaultVtxo;
pub use error::Error;
pub use error::ErrorContext;
pub use history::generate_incoming_vtxo_transaction_history;
pub use history::generate_outgoing_vtxo_transaction_history;
pub use history::ArkTransaction;
pub use script::extract_sequence_from_csv_sig_script;

pub const UNSPENDABLE_KEY: &str =
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub const VTXO_INPUT_INDEX: usize = 0;
