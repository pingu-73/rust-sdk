use bitcoin::secp256k1::PublicKey;
use bitcoin::XOnlyPublicKey;

pub fn to_zkp_pk(pk: PublicKey) -> zkp::PublicKey {
    zkp::PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn from_zkp_xonly(pk: zkp::XOnlyPublicKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&pk.serialize()).unwrap()
}
