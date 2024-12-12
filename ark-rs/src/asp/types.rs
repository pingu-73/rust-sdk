use crate::asp::Error;
use crate::generated;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::PublicKey;

#[derive(Clone, Debug)]
pub struct Info {
    pub pk: PublicKey,
    pub round_lifetime: bitcoin::Sequence,
    pub unilateral_exit_delay: bitcoin::Sequence,
    pub round_interval: i64,
    pub network: Network,
    pub dust: Amount,
    pub boarding_descriptor_template: String,
    pub vtxo_descriptor_templates: Vec<String>,
    pub forfeit_address: Address,
}

impl TryFrom<generated::ark::v1::GetInfoResponse> for Info {
    type Error = Error;

    fn try_from(value: generated::ark::v1::GetInfoResponse) -> Result<Self, Self::Error> {
        let pk = value.pubkey.parse().map_err(Error::conversion)?;

        let round_lifetime = bitcoin::Sequence::from_seconds_ceil(value.round_lifetime as u32)
            .map_err(Error::conversion)?;

        let unilateral_exit_delay =
            bitcoin::Sequence::from_seconds_ceil(value.unilateral_exit_delay as u32)
                .map_err(Error::conversion)?;

        let network = value.network.parse().map_err(Error::conversion)?;

        let forfeit_address: Address<NetworkUnchecked> =
            value.forfeit_address.parse().map_err(Error::conversion)?;
        let forfeit_address = forfeit_address
            .require_network(network)
            .map_err(Error::conversion)?;

        Ok(Info {
            pk,
            round_lifetime,
            unilateral_exit_delay,
            round_interval: value.round_interval,
            network,
            dust: Amount::from_sat(value.dust as u64),
            boarding_descriptor_template: value.boarding_descriptor_template,
            vtxo_descriptor_templates: value.vtxo_descriptor_templates,
            forfeit_address,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VtxoOutPoint {
    pub outpoint: Option<OutPoint>,
    pub spent: bool,
    pub round_txid: String,
    pub spent_by: String,
    pub expire_at: i64,
    pub swept: bool,
    pub is_oor: bool,
    pub redeem_tx: String,
    pub amount: Amount,
    pub pubkey: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct ListVtxo {
    pub spent: Vec<VtxoOutPoint>,
    pub spendable: Vec<VtxoOutPoint>,
}

impl TryFrom<&generated::ark::v1::Vtxo> for VtxoOutPoint {
    type Error = Error;

    fn try_from(value: &generated::ark::v1::Vtxo) -> Result<Self, Self::Error> {
        Ok(VtxoOutPoint {
            outpoint: value
                .outpoint
                .clone()
                .map(|out| {
                    Ok(OutPoint {
                        txid: out.txid.parse().map_err(Error::conversion)?,
                        vout: out.vout,
                    })
                })
                .transpose()?,
            spent: value.spent,
            round_txid: value.round_txid.clone(),
            spent_by: value.spent_by.clone(),
            expire_at: value.expire_at,
            swept: value.swept,
            is_oor: value.is_oor,
            redeem_tx: value.redeem_tx.clone(),
            amount: Amount::from_sat(value.amount),
            pubkey: value.pubkey.clone(),
            created_at: value.created_at,
        })
    }
}
