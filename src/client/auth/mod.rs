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
    pub(crate) fn from_is_master(_reply: &IsMasterCommandResponse) -> AuthMechanism {
        // TODO: RUST-87 check for SCRAM-SHA-256 first
        AuthMechanism::SCRAMSHA1
    }
}

impl Display for AuthMechanism {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            AuthMechanism::SCRAMSHA1 => write!(f, "SCRAM-SHA-1"),
            AuthMechanism::SCRAMSHA256 => write!(f, "SCRAM-SHA-256"),
            AuthMechanism::MONGODBCR => write!(f, "MONGODB-CR"),
            AuthMechanism::GSSAPI => write!(f, "GSSAPI"),
            AuthMechanism::MONGODBX509 => write!(f, "MONGODB-X509"),
            AuthMechanism::PLAIN => write!(f, "PLAIN"),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
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
    // MongoDB handshake
    let ismaster_response =
        pool::is_master_stream(stream, true, Some(credential.clone())).or::<Error>(Err(
            ErrorKind::AuthenticationError("isMaster failed".to_string()).into(),
        ))?;

    // Verify server can authenticate
    let server_type = ServerType::from_ismaster_response(&ismaster_response.command_response);
    if !server_type.can_auth() {
        return Ok(());
    };

    // Use the user-specified mechanism or get one from the isMaster response
    let mechanism = credential
        .mechanism()
        .unwrap_or_else(|| AuthMechanism::from_is_master(&ismaster_response.command_response));

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
