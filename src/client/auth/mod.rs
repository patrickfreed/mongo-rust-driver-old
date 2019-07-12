pub(crate) mod scram;

use std::{
    fmt,
    fmt::{Display, Formatter},
    io::{Read, Write},
};

use base64;
use bson::Document;
use rand::Rng;

use crate::{
    command_responses::IsMasterCommandResponse,
    error::{Error, ErrorKind, Result},
    pool,
    topology::ServerType,
};

const SCRAM_SHA_1_STR: &str = "SCRAM-SHA-1";
const SCRAM_SHA_256_STR: &str = "SCRAM-SHA-256";
const MONGODB_CR_STR: &str = "MONGODB-CR";
const GSSAPI_STR: &str = "GSSAPI";
const MONGODB_X509_STR: &str = "MONGODB-X509";
const PLAIN_STR: &str = "PLAIN";

#[derive(Clone, PartialEq, Debug)]
pub enum AuthMechanism {
    MONGODBCR,
    SCRAMSHA1,
    SCRAMSHA256,
    MONGODBX509,
    GSSAPI,
    PLAIN,
}

impl AuthMechanism {
    pub(crate) fn from_str(str: &str) -> Option<Self> {
        match str {
            SCRAM_SHA_1_STR => Some(AuthMechanism::SCRAMSHA1),
            SCRAM_SHA_256_STR => Some(AuthMechanism::SCRAMSHA256),
            MONGODB_CR_STR => Some(AuthMechanism::MONGODBCR),
            MONGODB_X509_STR => Some(AuthMechanism::MONGODBX509),
            GSSAPI_STR => Some(AuthMechanism::GSSAPI),
            PLAIN_STR => Some(AuthMechanism::PLAIN),
            _ => None,
        }
    }

    pub(crate) fn from_is_master(_reply: &IsMasterCommandResponse) -> AuthMechanism {
        // TODO: RUST-87 check for SCRAM-SHA-256 first
        AuthMechanism::SCRAMSHA1
    }

    /// Get the default authSource for a given mechanism depending on the database provided in the
    /// connection string.
    pub(crate) fn default_source(&self, uri_db: Option<&str>) -> String {
        // TODO: fill in others as they're implemented.
        match self {
            AuthMechanism::SCRAMSHA1 | AuthMechanism::SCRAMSHA256 => uri_db.unwrap_or("admin").to_string(),
            _ => "".to_string(),
        }
    }
}

impl Display for AuthMechanism {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            AuthMechanism::SCRAMSHA1 => f.write_str(SCRAM_SHA_1_STR),
            AuthMechanism::SCRAMSHA256 => f.write_str(SCRAM_SHA_256_STR),
            AuthMechanism::MONGODBCR => f.write_str(MONGODB_CR_STR),
            AuthMechanism::GSSAPI => f.write_str(GSSAPI_STR),
            AuthMechanism::MONGODBX509 => f.write_str(MONGODB_X509_STR),
            AuthMechanism::PLAIN => f.write_str(PLAIN_STR),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct MongoCredential {
    pub username: Option<String>,

    pub source: Option<String>,

    pub password: Option<String>,

    pub mechanism: Option<AuthMechanism>,

    pub mechanism_properties: Option<Document>,
}

impl MongoCredential {
    pub fn username(&self) -> Option<&str> {
        match &self.username {
            Some(s) => Some(s.as_str()),
            None => None,
        }
    }

    pub fn source(&self) -> Option<&str> {
        match &self.source {
            Some(s) => (Some(s.as_str())),
            None => None,
        }
    }

    pub fn mechanism(&self) -> Option<AuthMechanism> {
        self.mechanism.clone()
    }

    pub fn password(&self) -> Option<&str> {
        match &self.password {
            Some(p) => Some(p.as_str()),
            None => None,
        }
    }

    pub fn mechanism_properties(&self) -> Option<&Document> {
        match &self.mechanism_properties {
            Some(mp) => Some(&mp),
            None => None,
        }
    }

    /// If the mechanism is missing, append the appropriate mechanism negotiation key-value-pair to
    /// the provided isMaster command document.
    pub(crate) fn append_needed_mechanism_negotiation(&self, command: &mut Document) {
        match (self.username(), self.mechanism()) {
            (Some(username), None) => {
                command.insert(
                    "saslSupportedMechs",
                    format!(
                        "{}.{}",
                        self.source()
                            .unwrap_or(AuthMechanism::SCRAMSHA1.default_source(None).as_str()),
                        username
                    ),
                );
            }
            _ => {}
        }
    }
}

pub(crate) fn generate_nonce() -> String {
    let mut result = vec![0; 32];
    let mut rng = rand::thread_rng();

    for i in 0..32 {
        result[i] = rng.gen()
    }
    base64::encode(result.as_slice())
}

/// Creates an `AuthenticationError` for the given mechanism with the provided reason.
pub(crate) fn error(mechanism_name: &str, reason: &str) -> Error {
    ErrorKind::AuthenticationError(format!("{} failure: {}", mechanism_name, reason)).into()
}

/// Creates an `AuthenticationError` for the given mechanism with a generic "unknown" message.
pub(crate) fn unknown_error(mechanism_name: &str) -> Error {
    error(mechanism_name, "internal error")
}

/// Creates an `AuthenticationError` for the given mechanism when the server response is invalid.
pub(crate) fn invalid_response(mechanism_name: &str) -> Error {
    error(mechanism_name, "invalid server response")
}

pub(crate) fn authenticate_stream<T: Read + Write>(
    stream: &mut T,
    credential: &MongoCredential,
) -> Result<()> {
    // Perform handshake and negotiate mechanism if necessary
    let (ismaster_response, mechanism) = match credential.mechanism() {
        Some(mech) => {
            let resp = pool::is_master_stream(stream, true, None).or::<Error>(Err(
                ErrorKind::AuthenticationError("isMaster failed".to_string()).into(),
            ))?;
            (resp, mech)
        }
        None => {
            let resp = pool::is_master_stream(stream, true, Some(credential.clone())).or::<Error>(
                Err(ErrorKind::AuthenticationError("isMaster failed".to_string()).into()),
            )?;
            let mech = AuthMechanism::from_is_master(&resp.command_response);
            (resp, mech)
        }
    };

    // Verify server can authenticate
    let server_type = ServerType::from_ismaster_response(&ismaster_response.command_response);
    if !server_type.can_auth() {
        return Ok(());
    };

    // Authenticate according to the decided upon mechanism.
    match mechanism {
        AuthMechanism::SCRAMSHA1 => {
            scram::authenticate_stream(stream, credential, scram::ScramVersion::SHA1)
        }
        AuthMechanism::MONGODBCR => bail!(ErrorKind::AuthenticationError(
            "MONGODB-CR is deprecated and will not be supported by this driver. Use SCRAM for \
             password-based authentication instead"
                .to_string()
        )),
        _ => bail!(ErrorKind::AuthenticationError(format!(
            "Authentication mechanism {:?} not yet implemented.",
            mechanism
        ))),
    }
}
