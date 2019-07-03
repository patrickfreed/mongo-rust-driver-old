pub(crate) mod scram;

use crate::{command_responses::IsMasterCommandResponse, error::Result};
use base64;
use bson::Document;
use hmac::{Hmac, Mac};
use rand::{distributions::Alphanumeric, rngs::StdRng, CryptoRng, Rng};
use sha1::{Digest, Sha1};
use std::ops::BitXor;

#[derive(Clone, Debug)]
pub enum AuthMechanism {
    SCRAMSHA1,
}

impl AuthMechanism {
    fn from_str(string: &str) -> Option<AuthMechanism> {
        match string {
            "SCRAM_SHA_1" => Some(AuthMechanism::SCRAMSHA1),
            _ => None,
        }
    }

    pub(crate) fn from_is_master(reply: &IsMasterCommandResponse) -> AuthMechanism {
        // TODO: RUST-87 check for SCRAM-SHA-256 first
        AuthMechanism::SCRAMSHA1
    }
}

#[derive(Clone)]
pub struct MongoCredential {
    pub username: String,

    pub source: String,

    pub password: Option<String>,

    pub mechanism: Option<AuthMechanism>,

    pub mechanism_properties: Option<Document>,
}

impl MongoCredential {
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    pub fn source(&self) -> &str {
        self.source.as_str()
    }

    pub fn mechanism(&self) -> Option<AuthMechanism> {
        self.mechanism.clone()
    }

    pub fn password(&self) -> Option<String> {
        self.password.clone()
    }

    pub fn mechanism_properties(&self) -> Option<Document> {
        self.mechanism_properties.clone()
    }
}

pub fn generate_nonce() -> String {
    let mut result = vec![0, 32];
    let mut rng = rand::thread_rng();

    for i in 0..32 {
        result[i] = rng.gen()
    }
    base64::encode(result.as_slice())
}
