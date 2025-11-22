use fastcrypto::hash::{HashFunction, Sha256, Blake2b256};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519Signature};
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1Signature};
use fastcrypto::secp256r1::{Secp256r1KeyPair, Secp256r1Signature};
use fastcrypto::bls12381::min_sig::{BLS12381KeyPair, BLS12381Signature};
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes, VerifyingKey};
use std::sync::Arc;
use rand::thread_rng;

uniffi::setup_scaffolding!();

#[derive(uniffi::Enum)]
pub enum HashType {
    Sha256,
    Blake2b256,
}

#[uniffi::export]
pub fn hash(data: Vec<u8>, algorithm: HashType) -> Vec<u8> {
    match algorithm {
        HashType::Sha256 => {
            let digest = Sha256::digest(&data);
            digest.to_vec()
        }
        HashType::Blake2b256 => {
            let digest = Blake2b256::digest(&data);
            digest.to_vec()
        }
    }
}

#[uniffi::export]
pub fn hex_encode(data: Vec<u8>) -> String {
    hex::encode(data)
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FastCryptoError {
    #[error("{msg}")]
    Generic { msg: String },
}

#[uniffi::export]
pub fn hex_decode(data: String) -> Result<Vec<u8>, FastCryptoError> {
    hex::decode(data).map_err(|e| FastCryptoError::Generic {
        msg: e.to_string(),
    })
}

// --- Ed25519 ---

#[derive(uniffi::Object)]
pub struct Ed25519KeyPairWrapper(Ed25519KeyPair);

#[uniffi::export]
impl Ed25519KeyPairWrapper {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        let mut rng = thread_rng();
        let keypair = Ed25519KeyPair::generate(&mut rng);
        Arc::new(Self(keypair))
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, FastCryptoError> {
        let keypair = Ed25519KeyPair::from_bytes(&bytes)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
        Ok(Arc::new(Self(keypair)))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.public().as_bytes().to_vec()
    }

    pub fn sign(&self, msg: Vec<u8>) -> Vec<u8> {
        self.0.sign(&msg).as_bytes().to_vec()
    }

    pub fn verify(&self, msg: Vec<u8>, signature: Vec<u8>) -> Result<bool, FastCryptoError> {
         let sig = Ed25519Signature::from_bytes(&signature)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
         Ok(self.0.public().verify(&msg, &sig).is_ok())
    }
}

// --- Secp256r1 ---

#[derive(uniffi::Object)]
pub struct Secp256r1KeyPairWrapper(Secp256r1KeyPair);

#[uniffi::export]
impl Secp256r1KeyPairWrapper {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        let mut rng = thread_rng();
        let keypair = Secp256r1KeyPair::generate(&mut rng);
        Arc::new(Self(keypair))
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, FastCryptoError> {
        let keypair = Secp256r1KeyPair::from_bytes(&bytes)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
        Ok(Arc::new(Self(keypair)))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.public().as_bytes().to_vec()
    }

    pub fn sign(&self, msg: Vec<u8>) -> Vec<u8> {
        self.0.sign(&msg).as_bytes().to_vec()
    }

    pub fn verify(&self, msg: Vec<u8>, signature: Vec<u8>) -> Result<bool, FastCryptoError> {
         let sig = Secp256r1Signature::from_bytes(&signature)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
         Ok(self.0.public().verify(&msg, &sig).is_ok())
    }
}

// --- BLS12-381 (Min Sig) ---

#[derive(uniffi::Object)]
pub struct BLS12381KeyPairWrapper(BLS12381KeyPair);

#[uniffi::export]
impl BLS12381KeyPairWrapper {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        let mut rng = thread_rng();
        let keypair = BLS12381KeyPair::generate(&mut rng);
        Arc::new(Self(keypair))
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, FastCryptoError> {
        let keypair = BLS12381KeyPair::from_bytes(&bytes)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
        Ok(Arc::new(Self(keypair)))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.public().as_bytes().to_vec()
    }

    pub fn sign(&self, msg: Vec<u8>) -> Vec<u8> {
        self.0.sign(&msg).as_bytes().to_vec()
    }

    pub fn verify(&self, msg: Vec<u8>, signature: Vec<u8>) -> Result<bool, FastCryptoError> {
         let sig = BLS12381Signature::from_bytes(&signature)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
         Ok(self.0.public().verify(&msg, &sig).is_ok())
    }
}


// --- Secp256k1 ---

#[derive(uniffi::Object)]
pub struct Secp256k1KeyPairWrapper(Secp256k1KeyPair);

#[uniffi::export]
impl Secp256k1KeyPairWrapper {
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        let mut rng = thread_rng();
        let keypair = Secp256k1KeyPair::generate(&mut rng);
        Arc::new(Self(keypair))
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, FastCryptoError> {
        let keypair = Secp256k1KeyPair::from_bytes(&bytes)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
        Ok(Arc::new(Self(keypair)))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.public().as_bytes().to_vec()
    }

    pub fn sign(&self, msg: Vec<u8>) -> Vec<u8> {
        self.0.sign(&msg).as_bytes().to_vec()
    }

    pub fn verify(&self, msg: Vec<u8>, signature: Vec<u8>) -> Result<bool, FastCryptoError> {
         let sig = Secp256k1Signature::from_bytes(&signature)
            .map_err(|e| FastCryptoError::Generic { msg: e.to_string() })?;
         Ok(self.0.public().verify(&msg, &sig).is_ok())
    }
}
