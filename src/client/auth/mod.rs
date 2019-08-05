pub(crate) mod scram;

use std::{
    borrow::Cow,
    io::{Read, Write},
    str::FromStr,
};

use base64;
use bson::Document;
use rand::Rng;

use crate::{
    command_responses::IsMasterCommandResponse,
    error::{Error, ErrorKind, Result},
    options::auth::scram::ScramVersion,
    pool,
    topology::ServerType,
};

const SCRAM_SHA_1_STR: &str = "SCRAM-SHA-1";
const SCRAM_SHA_256_STR: &str = "SCRAM-SHA-256";
const MONGODB_CR_STR: &str = "MONGODB-CR";
const GSSAPI_STR: &str = "GSSAPI";
const MONGODB_X509_STR: &str = "MONGODB-X509";
const PLAIN_STR: &str = "PLAIN";

/// The authentication mechanisms supported by MongoDB.
///
/// Note: not all of these mechanisms are currently supported by the driver.
#[derive(Clone, PartialEq, Debug)]
pub enum AuthMechanism {
    /// MongoDB Challenge Response nonce and MD5 based authentication system. It is currently
    /// deprecated and will never be supported by this driver.
    MongoDbCr,

    /// The SCRAM-SHA-1 mechanism as defined in [RFC 5802](http://tools.ietf.org/html/rfc5802).
    ///
    /// See the [MongoDB documentation](https://docs.mongodb.com/manual/core/security-scram/) for more information.
    ScramSha1,

    /// The SCRAM-SHA-256 mechanism which extends [RFC 5802](http://tools.ietf.org/html/rfc5802) and is formally defined in [RFC 7677](https://tools.ietf.org/html/rfc7677).
    ///
    /// See the [MongoDB documentation](https://docs.mongodb.com/manual/core/security-scram/) for more information.
    ScramSha256,

    /// The MONGODB-X509 mechanism based on the usage of X.509 certificates to validate a client
    /// where the distinguished subject name of the client certificate acts as the username.
    ///
    /// See the [MongoDB documentation](https://docs.mongodb.com/manual/core/security-x.509/) for more information.
    ///
    /// Note: This mechanism is not currently supported by this driver but will be in the future.
    MongoDbX509,

    /// Kerberos authentication mechanism as defined in [RFC 4752](http://tools.ietf.org/html/rfc4752).
    ///
    /// See the [MongoDB documentation](https://docs.mongodb.com/manual/core/kerberos/) for more information.
    ///
    /// Note: This mechanism is not currently supported by this driver but will be in the future.
    Gssapi,

    /// The SASL PLAIN mechanism, as defined in [RFC 4616](), is used in MongoDB to perform LDAP
    /// authentication and cannot be used for any other type of authenticaiton.
    /// Since the credentials are stored outside of MongoDB, the "$external" database must be used
    /// for authentication.
    ///
    /// See the [MongoDB documentation](https://docs.mongodb.com/manual/core/security-ldap/#ldap-proxy-authentication) for more information on LDAP authentication.
    ///
    /// Note: This mechanism is not currently supported by this driver but will be in the future.
    Plain,
}

impl AuthMechanism {
    /// Get an `AuthenticationMechanism` from the response to an isMaster.
    /// If no mechanisms are present in the response, SCRAM-SHA-1 will be chosen by default.
    pub(crate) fn from_is_master(reply: &IsMasterCommandResponse) -> AuthMechanism {
        let scram_sha_256_found = reply
            .sasl_supported_mechs
            .as_ref()
            .map(|ms| ms.iter().any(|m| m == AuthMechanism::ScramSha256.as_str()))
            .unwrap_or(false);

        if scram_sha_256_found {
            AuthMechanism::ScramSha256
        } else {
            AuthMechanism::ScramSha1
        }
    }

    /// Determines if the provided credentials have the required information to perform
    /// authentication.
    pub fn validate_credential(&self, credential: &Credential) -> Result<()> {
        // TODO: X509 (RUST-147)
        // TODO: GSSAPI (RUST-196)
        // TODO: PLAIN (RUST-197)
        match self {
            AuthMechanism::ScramSha1 | AuthMechanism::ScramSha256 => {
                match credential.username {
                    Some(ref user) => {
                        if user.is_empty() {
                            bail!(ErrorKind::ArgumentError(
                                "Username must be non-zero length in SCRAM authentication"
                                    .to_string()
                            ))
                        }
                    }
                    None => bail!(ErrorKind::ArgumentError(
                        "Username must be provided for SCRAM authentication".to_string()
                    )),
                };

                if credential.password.is_none() {
                    bail!(ErrorKind::ArgumentError(
                        "Password must be provided for SCRAM authentication".to_string()
                    ))
                };

                if credential.mechanism_properties.is_some() {
                    bail!(ErrorKind::ArgumentError(
                        "Mechanism properties must not be provided for SCRAM authentication"
                            .to_string()
                    ))
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Get the default authSource for a given mechanism depending on the database provided in the
    /// connection string.
    pub(crate) fn default_source(&self, uri_db: Option<&str>) -> String {
        match self {
            AuthMechanism::ScramSha1 | AuthMechanism::ScramSha256 | AuthMechanism::MongoDbCr => {
                uri_db.unwrap_or("admin").to_string()
            }
            AuthMechanism::Gssapi | AuthMechanism::MongoDbX509 => "$external".to_string(),
            AuthMechanism::Plain => uri_db.unwrap_or("$external").to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            AuthMechanism::ScramSha1 => SCRAM_SHA_1_STR,
            AuthMechanism::ScramSha256 => SCRAM_SHA_256_STR,
            AuthMechanism::Gssapi => GSSAPI_STR,
            AuthMechanism::MongoDbCr => MONGODB_CR_STR,
            AuthMechanism::MongoDbX509 => MONGODB_X509_STR,
            AuthMechanism::Plain => PLAIN_STR,
        }
    }

    pub(crate) fn authenticate_stream<T: Read + Write>(
        &self,
        stream: &mut T,
        credential: &Credential,
    ) -> Result<()> {
        match self {
            AuthMechanism::ScramSha1 => ScramVersion::Sha1.authenticate_stream(stream, credential),
            AuthMechanism::ScramSha256 => {
                ScramVersion::Sha256.authenticate_stream(stream, credential)
            }
            AuthMechanism::MongoDbCr => bail!(ErrorKind::AuthenticationError(
                "MONGODB-CR is deprecated and not supported by this driver. Use SCRAM for \
                 password-based authentication instead"
                    .to_string()
            )),
            _ => bail!(ErrorKind::AuthenticationError(format!(
                "Authentication mechanism {:?} not yet implemented.",
                self
            ))),
        }
    }
}

impl FromStr for AuthMechanism {
    type Err = Error;

    fn from_str(str: &str) -> Result<Self> {
        match str {
            SCRAM_SHA_1_STR => Ok(AuthMechanism::ScramSha1),
            SCRAM_SHA_256_STR => Ok(AuthMechanism::ScramSha256),
            MONGODB_CR_STR => Ok(AuthMechanism::MongoDbCr),
            MONGODB_X509_STR => Ok(AuthMechanism::MongoDbX509),
            GSSAPI_STR => Ok(AuthMechanism::Gssapi),
            PLAIN_STR => Ok(AuthMechanism::Plain),
            _ => Err(ErrorKind::ArgumentError(
                format!("invalid mechanism string: {}", str).to_string(),
            )
            .into()),
        }
    }
}

/// A struct containing authentication information.
///
/// Some fields (mechanism and source) may be omitted and will either be negotiated or assigned a
/// default value, depending on the values of other fields in the credential.
#[derive(Clone, PartialEq, Debug, Default, TypedBuilder)]
pub struct Credential {
    /// The username to authenticate with. This applies to all mechanisms but may be omitted when
    /// authenticating via MONGODB-X509.
    #[builder(default)]
    pub username: Option<String>,

    /// The database used to authenticate. This applies to all mechanisms and defaults to "admin"
    /// in SCRAM authentication mechanisms and "$external" for GSSAPI and MONGODB-X509.
    #[builder(default)]
    pub source: Option<String>,

    /// The password to authenticate with. This does not apply to all mechanisms.
    #[builder(default)]
    pub password: Option<String>,

    /// Which authentication mechanism to use. If not provided, one will be negotiated with the
    /// server.
    #[builder(default)]
    pub mechanism: Option<AuthMechanism>,

    /// Additional properties for the given mechanism.
    #[builder(default)]
    pub mechanism_properties: Option<Document>,
}

impl Credential {
    /// If the mechanism is missing, append the appropriate mechanism negotiation key-value-pair to
    /// the provided isMaster command document.
    pub(crate) fn append_needed_mechanism_negotiation(&self, command: &mut Document) {
        if let (Some(username), None) = (self.username.as_ref(), self.mechanism.as_ref()) {
            let source = match self.source.as_ref() {
                Some(src) => Cow::Borrowed(src),
                // Mechanism negotiation uses the SCRAM family's default db, per the spec.
                None => Cow::Owned(AuthMechanism::ScramSha1.default_source(None)),
            };

            command.insert(
                "saslSupportedMechs",
                format!("{}.{}", source.as_str(), username),
            );
        }
    }

    /// Attempts to authenticate a stream according this credential, returning an error
    /// result on failure. A mechanism may be negotiated if one is not provided as part of the
    /// credential.
    pub(crate) fn authenticate_stream<T: Read + Write>(&self, stream: &mut T) -> Result<()> {
        // Perform handshake and negotiate mechanism if necessary.
        let ismaster_response = match pool::is_master_stream(stream, true, Some(self)) {
            Ok(resp) => resp,
            Err(_) => bail!(ErrorKind::AuthenticationError(
                "isMaster failed".to_string()
            )),
        };

        // Verify server can authenticate.
        let server_type = ServerType::from_ismaster_response(&ismaster_response.command_response);
        if !server_type.can_auth() {
            return Ok(());
        };

        let mechanism = match self.mechanism {
            None => Cow::Owned(AuthMechanism::from_is_master(
                &ismaster_response.command_response,
            )),
            Some(ref m) => Cow::Borrowed(m),
        };

        // Authenticate according to the chosen mechanism.
        mechanism.authenticate_stream(stream, self)
    }
}

pub(crate) fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let result: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    base64::encode(result.as_slice())
}

#[cfg(test)]
mod tests {
    use crate::{command_responses::IsMasterCommandResponse, options::auth::AuthMechanism};

    lazy_static! {
        static ref MECHS: [String; 2] = [
            AuthMechanism::ScramSha1.as_str().to_string(),
            AuthMechanism::ScramSha256.as_str().to_string()
        ];
    }

    #[test]
    fn negotiate_both_scram() {
        let is_master_both = IsMasterCommandResponse {
            sasl_supported_mechs: Some(MECHS.to_vec()),
            ..Default::default()
        };
        assert_eq!(
            AuthMechanism::from_is_master(&is_master_both),
            AuthMechanism::ScramSha256
        );
    }

    #[test]
    fn negotiate_sha1_only() {
        let is_master_sha1 = IsMasterCommandResponse {
            sasl_supported_mechs: Some(MECHS[0..=0].to_vec()),
            ..Default::default()
        };
        assert_eq!(
            AuthMechanism::from_is_master(&is_master_sha1),
            AuthMechanism::ScramSha1
        );
    }

    #[test]
    fn negotiate_sha256_only() {
        let is_master_sha256 = IsMasterCommandResponse {
            sasl_supported_mechs: Some(MECHS[1..=1].to_vec()),
            ..Default::default()
        };
        assert_eq!(
            AuthMechanism::from_is_master(&is_master_sha256),
            AuthMechanism::ScramSha256
        );
    }

    #[test]
    fn negotiate_none() {
        let is_master_none: IsMasterCommandResponse = Default::default();
        assert_eq!(
            AuthMechanism::from_is_master(&is_master_none),
            AuthMechanism::ScramSha1
        );
    }

    #[test]
    fn negotiate_mangled() {
        let is_master_mangled = IsMasterCommandResponse {
            sasl_supported_mechs: Some(
                ["NOT A MECHANISM".to_string(), "OTHER".to_string()].to_vec(),
            ),
            ..Default::default()
        };
        assert_eq!(
            AuthMechanism::from_is_master(&is_master_mangled),
            AuthMechanism::ScramSha1
        );
    }
}
