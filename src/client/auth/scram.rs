use std::{
    fmt,
    fmt::{Display, Formatter},
    io::{Read, Write},
    ops::{BitXor, Deref, Range},
    str,
};

use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2;
use sha1::{Digest, Sha1};
use stringprep;

use bson::{spec::BinarySubtype, Bson, Document};

use crate::{
    client::{auth, auth::MongoCredential},
    error::{Error, Result},
    pool,
};

// The single letter attribute keys in SCRAM messages.
const ITERATION_COUNT_KEY: char = 'i';
const ERROR_KEY: char = 'e';
const PROOF_KEY: char = 'p';
const VERIFIER_KEY: char = 'v';
const NONCE_KEY: char = 'r';
const SALT_KEY: char = 's';
const CHANNEL_BINDING_KEY: char = 'c';

/// Constant specifying that we won't be using channel binding.
const NO_CHANNEL_BINDING: char = 'n';

/// The minimum number of iterations of the hash function that we will accept from the server.
const MIN_ITERATION_COUNT: usize = 4096;

/// The versions of SCRAM supported by the driver (classified according to hash function used).
pub(crate) enum ScramVersion {
    SHA1,
}

impl ScramVersion {
    //    fn from(mechanism: &AuthMechanism) -> Result<Self> {
    //        match mechanism {
    //            AuthMechanism::SCRAMSHA1 => Ok(ScramVersion::SHA1),
    //            AuthMechanism::SCRAMSHA256 => bail!(ErrorKind::AuthenticationError(
    //                "SCRAM-SHA-256 not yet implemented".to_string()
    //            )),
    //            _ => bail!(ErrorKind::AuthenticationError(format!(
    //                "{} is not a SCRAM authentication mechanism",
    //                mechanism
    //            ))),
    //        }
    //    }

    /// HMAC function used as part of SCRAM authentication.
    fn hmac(&self, key: &[u8], str: &[u8]) -> Result<Vec<u8>> {
        match self {
            ScramVersion::SHA1 => {
                let mut mac =
                    Hmac::<Sha1>::new_varkey(key).or(Err(auth::unknown_error("SCRAM")))?;
                mac.input(str);
                Ok(mac.result().code().to_vec())
            }
        }
    }

    /// The "h" function defined in the SCRAM RFC.
    fn h(&self, str: &[u8]) -> Vec<u8> {
        match self {
            ScramVersion::SHA1 => {
                let mut sha1 = Sha1::new();
                sha1.input(str);
                sha1.result().to_vec()
            }
        }
    }

    /// The "h_i" function as defined in the SCRAM RFC.
    fn h_i(&self, str: &str, salt: &[u8], iterations: usize) -> Vec<u8> {
        match self {
            ScramVersion::SHA1 => {
                let mut buf = vec![0u8; 20];
                pbkdf2::pbkdf2::<Hmac<Sha1>>(str.as_bytes(), salt, iterations, &mut buf);
                buf
            }
        }
        // hand rolled version I wrote before I realized there was a crate for this
        //    let mut u: Vec<Vec<u8>> = vec![];
        //    let mut salted = salt.to_vec();
        //    salted.extend_from_slice(vec![0u8, 0u8, 0u8, 1u8].as_slice());
        //
        //    u.push(hmac(str.as_bytes(), salted.as_slice(), scram));
        //    for i in 1..iterations {
        //        u.push(hmac(str.as_bytes(), u[i - 1].as_slice(), scram));
        //    }
        //
        //    u.iter().fold(vec![0u8; u[0].len()], |output, next| {
        //        xor(output.as_slice(), next.as_slice())
        //    })
    }
}

impl Display for ScramVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ScramVersion::SHA1 => write!(f, "SCRAM-SHA-1"),
        }
    }
}

pub fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());

    lhs.iter()
        .zip(rhs.iter())
        .map(|(l, r)| l.bitxor(r.clone()))
        .collect()
}

/// Gets the salted password. Will first check for cached credentials and return those if possible.
/// Updates the cache to store any computed credentials.
fn get_salted_password(
    credential: &MongoCredential,
    server_first: &ServerFirst,
    scram: &ScramVersion,
) -> Result<Vec<u8>> {
    // TODO: check for cached credentials here
    let mut md5 = Md5::new();
    md5.input(format!(
        "{}:mongo:{}",
        credential.username(),
        credential.password().unwrap()
    ));
    let hashed_password = hex::encode(md5.result());
    let normalized_password = stringprep::saslprep(hashed_password.as_str())
        .or::<Error>(Err(auth::error("SCRAM", "saslprep failure")))?;
    Ok(scram.h_i(
        normalized_password.deref(),
        server_first.salt(),
        server_first.i(),
    ))
}

/// Parses a string slice of the form "<expected_key>=<body>" into "<body>", if possible.
fn parse_kvp(str: &str, expected_key: char) -> Result<String> {
    if str.chars().nth(0) != Some(expected_key) || str.chars().nth(1) != Some('=') {
        Err(auth::invalid_response("SCRAM"))
    } else {
        Ok(str.chars().skip(2).collect())
    }
}

/// Model of the first message sent by the client.
struct ClientFirst {
    message: String,

    gs2_header: Range<usize>,

    bare: Range<usize>,
}

impl ClientFirst {
    fn new(username: &str, nonce: &str) -> Self {
        let gs2_header = format!("{},,", NO_CHANNEL_BINDING);
        let bare = format!("n={},r={}", username, nonce);
        let full = format!("{}{}", &gs2_header, &bare);
        let end = full.len();
        ClientFirst {
            message: full,
            gs2_header: Range {
                start: 0,
                end: gs2_header.len(),
            },
            bare: Range {
                start: gs2_header.len(),
                end,
            },
        }
    }

    fn bare_message(&self) -> &str {
        &self.message[self.bare.clone()]
    }

    fn gs2_header(&self) -> &str {
        &self.message[self.gs2_header.clone()]
    }

    fn message(&self) -> &str {
        &self.message[..]
    }

    fn to_command(&self, scram: &ScramVersion) -> Document {
        doc! {
            "saslStart": 1,
            "mechanism": scram.to_string(),
            "payload": Bson::Binary(BinarySubtype::Generic, self.message().as_bytes().to_vec())
        }
    }
}

/// Model of the first message received from the server.
///
/// This MUST be validated before sending the `ClientFinal` message back to the server.
struct ServerFirst {
    conversation_id: Bson,
    done: bool,
    message: String,
    nonce: String,
    salt: Vec<u8>,
    i: usize,
}

impl ServerFirst {
    fn parse(response: Document) -> Result<Self> {
        let conversation_id = response
            .get("conversationId")
            .ok_or(auth::error("SCRAM", "mismatched conversationId's"))?;
        let payload = match response.get_binary_generic("payload") {
            Ok(p) => p,
            Err(_) => return Err(auth::invalid_response("SCRAM")),
        };
        let done = response
            .get_bool("done")
            .or::<Error>(Err(auth::invalid_response("SCRAM")))?;
        let message = str::from_utf8(payload).or::<Error>(Err(auth::invalid_response("SCRAM")))?;

        let parts: Vec<&str> = message.split(",").collect();

        if parts.len() < 3 {
            return Err(auth::invalid_response("SCRAM"));
        };

        let full_nonce = parse_kvp(parts[0], NONCE_KEY)?;

        let salt = base64::decode(parse_kvp(parts[1], SALT_KEY)?.as_str()).unwrap();

        let i: usize = match parse_kvp(parts[2], ITERATION_COUNT_KEY)?.parse() {
            Ok(num) => num,
            Err(_) => return Err(auth::error("SCRAM", "iteration count invalid")),
        };

        Ok(ServerFirst {
            conversation_id: conversation_id.clone(),
            done,
            message: message.to_string(),
            nonce: full_nonce,
            salt,
            i,
        })
    }

    fn conversation_id(&self) -> &Bson {
        &self.conversation_id
    }

    fn message(&self) -> &str {
        self.message.as_str()
    }

    fn nonce(&self) -> &str {
        self.nonce.as_str()
    }

    fn salt(&self) -> &[u8] {
        self.salt.as_slice()
    }

    fn i(&self) -> usize {
        self.i
    }

    fn validate(&self, nonce: &str) -> Result<()> {
        if self.done {
            Err(auth::error("SCRAM", "handshake terminated early"))
        } else if &self.nonce[0..nonce.len()] != nonce {
            Err(auth::error("SCRAM", "mismatched nonce"))
        } else if self.i < MIN_ITERATION_COUNT {
            Err(auth::error("SCRAM", "iteration count too low"))
        } else {
            Ok(())
        }
    }
}

/// Model of the final message sent by the client.
///
/// Contains the "AuthMessage" mentioned in the RFC used in computing the client and server
/// signatures.
struct ClientFinal {
    message: String,
    auth_message: String,
    conversation_id: Bson,
}

impl ClientFinal {
    fn new(
        salted_password: &[u8],
        client_first: &ClientFirst,
        server_first: &ServerFirst,
        scram: &ScramVersion,
    ) -> Result<Self> {
        let client_key = scram.hmac(salted_password, "Client Key".as_bytes())?;
        let stored_key = scram.h(client_key.as_slice());

        let without_proof = format!(
            "{}={},{}={}",
            CHANNEL_BINDING_KEY,
            base64::encode(client_first.gs2_header()),
            NONCE_KEY,
            server_first.nonce()
        );
        let auth_message = format!(
            "{},{},{}",
            client_first.bare_message(),
            server_first.message(),
            without_proof.as_str()
        );
        let client_signature = scram.hmac(stored_key.as_slice(), auth_message.as_bytes())?;
        let client_proof =
            base64::encode(xor(client_key.as_slice(), client_signature.as_slice()).as_slice());

        let message = format!("{},{}={}", without_proof, PROOF_KEY, client_proof);

        Ok(ClientFinal {
            message,
            auth_message,
            conversation_id: server_first.conversation_id().clone(),
        })
    }

    fn payload(&self) -> Bson {
        Bson::Binary(BinarySubtype::Generic, self.message().as_bytes().to_vec())
    }

    fn message(&self) -> &str {
        self.message.as_str()
    }

    fn auth_message(&self) -> &str {
        self.auth_message.as_str()
    }

    fn to_command(&self) -> Document {
        doc! {
            "saslContinue": 1,
            "conversationId": self.conversation_id.clone(),
            "payload": self.payload()
        }
    }
}

enum ServerFinalBody {
    Error(String),
    Verifier(String),
}

/// Model of the final message received from the server.
///
/// This MUST be validated before sending the final no-op message to the server.
struct ServerFinal {
    conversation_id: Bson,
    done: bool,
    body: ServerFinalBody,
}

impl ServerFinal {
    fn parse(response: Document) -> Result<Self> {
        let conversation_id = response
            .get("conversationId")
            .ok_or(auth::invalid_response("SCRAM"))?;
        let done = response
            .get_bool("done")
            .or::<Error>(Err(auth::invalid_response("SCRAM")))?;
        let payload = response
            .get_binary_generic("payload")
            .or::<Error>(Err(auth::invalid_response("SCRAM")))?;
        let message = str::from_utf8(payload).or::<Error>(Err(auth::invalid_response("SCRAM")))?;

        let first = message
            .chars()
            .nth(0)
            .ok_or(auth::invalid_response("SCRAM"))?;
        let body = if first == ERROR_KEY {
            let error = parse_kvp(message, ERROR_KEY)?;
            ServerFinalBody::Error(error)
        } else if first == VERIFIER_KEY {
            let verifier = parse_kvp(message, VERIFIER_KEY)?;
            ServerFinalBody::Verifier(verifier)
        } else {
            return Err(auth::invalid_response("SCRAM"));
        };

        Ok(ServerFinal {
            conversation_id: conversation_id.clone(),
            done,
            body,
        })
    }

    fn validate(
        &self,
        salted_password: &[u8],
        client_final: &ClientFinal,
        scram: &ScramVersion,
    ) -> Result<()> {
        if self.done {
            return Err(auth::error("SCRAM", "handshake terminated early"));
        };

        if &self.conversation_id != &client_final.conversation_id {
            return Err(auth::error("SCRAM", "mismatched conversationId's"));
        };

        match &self.body {
            ServerFinalBody::Verifier(body) => {
                let server_key = scram.hmac(salted_password, "Server Key".as_bytes())?;
                let server_signature = scram.hmac(
                    server_key.as_slice(),
                    client_final.auth_message().as_bytes(),
                )?;
                if base64::encode(server_signature.as_slice()).as_str() == body {
                    Ok(())
                } else {
                    Err(auth::error("SCRAM", "mismatched server signatures"))
                }
            }
            ServerFinalBody::Error(err) => Err(auth::error("SCRAM", err.as_str())),
        }
    }

    fn conversation_id(&self) -> &Bson {
        &self.conversation_id
    }
}

/// Perform SCRAM authentication for a given stream.
pub(crate) fn authenticate_stream<T: Read + Write>(
    stream: &mut T,
    credential: &MongoCredential,
    scram: ScramVersion,
) -> Result<()> {
    if credential.password().is_none() {
        return Err(auth::error("SCRAM", "no password supplied"));
    };

    if credential.mechanism_properties().is_some() {
        return Err(auth::error(
            "SCRAM",
            "mechanism properties MUST NOT be specified",
        ));
    };

    let nonce = auth::generate_nonce();

    let client_first = ClientFirst::new(credential.username.as_str(), nonce.as_str());

    let server_first_response = pool::run_command_stream(
        stream,
        credential.source.as_str(),
        client_first.to_command(&scram),
        false,
    )?;
    let server_first = ServerFirst::parse(server_first_response)?;
    server_first.validate(nonce.as_str())?;

    let salted_password = get_salted_password(credential, &server_first, &scram)?;

    let client_final = ClientFinal::new(
        salted_password.as_slice(),
        &client_first,
        &server_first,
        &scram,
    )?;

    let server_final_response = pool::run_command_stream(
        stream,
        credential.source.as_str(),
        client_final.to_command(),
        false,
    )?;
    let server_final = ServerFinal::parse(server_final_response)?;
    server_final.validate(salted_password.as_slice(), &client_final, &scram)?;

    // Normal SCRAM implementations would cease here. The following round trip is MongoDB
    // implementation specific and just consists of a client no-op followed by a server no-op
    // with "done: true".

    let noop = doc! {
        "saslContinue": 1,
        "conversationId": server_final.conversation_id().clone(),
        "payload": Bson::Binary(BinarySubtype::Generic, Vec::new())
    };
    let server_noop_response =
        pool::run_command_stream(stream, credential.source.as_str(), noop, false)?;

    if server_noop_response
        .get("conversationId")
        .and_then(|id| Some(id == server_final.conversation_id()))
        != Some(true)
    {
        return Err(auth::error("SCRAM", "mismatched conversationId's"));
    };

    if !server_noop_response.get_bool("done").unwrap_or(false) {
        return Err(auth::error(
            "SCRAM",
            "authentication did not complete successfully",
        ));
    }

    Ok(())
}
