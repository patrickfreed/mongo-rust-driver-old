use std::{
    io::{Read, Write},
    ops::{BitXor, Range},
    str,
};

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::{Digest, Sha1};

use crate::{
    client::{
        auth,
        auth::{AuthMechanism, MongoCredential},
    },
    error::{Error, ErrorKind, Result},
    pool::Connection,
};

const ITERATION_COUNT_KEY: char = 'i';
const ERROR_KEY: char = 'e';
const PROOF_KEY: char = 'p';
const VERIFIER_KEY: char = 'v';
const NONCE_KEY: char = 'r';
const SALT_KEY: char = 's';

const NO_CHANNEL_BINDING: char = 'n';

const MIN_ITERATION_COUNT: usize = 4096;

enum ScramVersion {
    SHA1,
}

pub fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());

    lhs.iter()
        .zip(rhs.iter())
        .map(|(l, r)| l.bitxor(r.clone()))
        .collect()
}

fn hmac(key: &[u8], str: &[u8], mechanism: &ScramVersion) -> Vec<u8> {
    match mechanism {
        ScramVersion::SHA1 => {
            let mut mac = Hmac::<Sha1>::new_varkey(key).unwrap();
            mac.input(str);

            mac.result().code().to_vec()
        }
    }
}

fn h(str: &[u8], mechanism: &ScramVersion) -> Vec<u8> {
    match mechanism {
        ScramVersion::SHA1 => {
            let mut sha1 = Sha1::new();
            sha1.input(str);
            sha1.result().to_vec()
        }
    }
}

fn h_i(str: &str, salt: &str, iterations: usize, scram: &ScramVersion) -> Vec<u8> {
    let mut u: Vec<Vec<u8>> = vec![];
    u.push(hmac(str.as_bytes(), format!("{}1", salt).as_bytes(), scram));
    for i in 1..iterations {
        u.push(hmac(str.as_bytes(), u[i - 1].as_slice(), scram));
    }

    u.iter().fold(vec![0u8, u[0].len() as u8], |output, next| {
        xor(output.as_slice(), next.as_slice())
    })
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
}

/// Model of the first message received from the server.
///
/// MUST validate that it contains the correct nonce and that the iteration count is sufficiently
/// high.
struct ServerFirst {
    message: String,
    nonce: String,
    salt: String,
    i: usize,
}

impl ServerFirst {
    fn parse(message: &str) -> Result<Self> {
        let parts: Vec<&str> = message.split(",").collect();

        if parts.len() < 3 {
            bail!(ErrorKind::AuthenticationError(
                "SCRAM failure: Bad server response".to_string()
            ))
        };

        let full_nonce = parse_kvp(parts[0], NONCE_KEY)?;

        let salt = parse_kvp(parts[1], SALT_KEY)?;

        let i: usize = match parse_kvp(parts[2], ITERATION_COUNT_KEY)?.parse() {
            Ok(num) => num,
            Err(_) => bail!(ErrorKind::AuthenticationError(
                "SCRAM failure: iteration count invalid".to_string()
            )),
        };

        Ok(ServerFirst {
            message: message.to_string(),
            nonce: full_nonce,
            salt,
            i,
        })
    }

    fn message(&self) -> &str {
        self.message.as_str()
    }

    fn nonce(&self) -> &str {
        self.nonce.as_str()
    }

    fn salt(&self) -> &str {
        self.salt.as_str()
    }

    fn i(&self) -> usize {
        self.i
    }

    fn validate(&self, nonce: &str) -> Result<()> {
        if &self.nonce[0..nonce.len()] != nonce {
            bail!(ErrorKind::AuthenticationError(
                "SCRAM Failure: bad nonce".to_string()
            ))
        }
        if self.i < MIN_ITERATION_COUNT {
            bail!(ErrorKind::AuthenticationError(
                "SCRAM Failure: iteration count too low".to_string()
            ))
        }
        Ok(())
    }
}

/// Model of the final message sent by the client.
///
/// Contains the "AuthMessage" mentioned in the RFC used in computing the client and server
/// signatures.
struct ClientFinal {
    message: String,
    auth_message: String,
    proof: Range<usize>,
}

impl ClientFinal {
    fn new(
        salted_password: &[u8],
        client_first: &ClientFirst,
        server_first: &ServerFirst,
        scram: &ScramVersion,
    ) -> Self {
        let client_key = hmac(salted_password, "Client Key".as_bytes(), scram);
        let stored_key = h(client_key.as_slice(), scram);

        let without_proof = format!(
            "c={},r={}",
            base64::encode(client_first.gs2_header()),
            server_first.nonce()
        );
        let auth_message = format!(
            "{},{},{}",
            client_first.bare_message(),
            server_first.message(),
            without_proof.as_str()
        );
        let client_signature = hmac(stored_key.as_slice(), auth_message.as_bytes(), scram);
        let client_proof = xor(client_key.as_slice(), client_signature.as_slice());

        let message = format!(
            "{},p={}",
            without_proof,
            str::from_utf8(client_proof.as_slice()).unwrap()
        );
        let end = message.len();
        ClientFinal {
            message,
            auth_message,
            proof: Range {
                start: without_proof.len(),
                end,
            },
        }
    }

    fn message(&self) -> &str {
        self.message.as_str()
    }

    fn auth_message(&self) -> &str {
        self.auth_message.as_str()
    }
}

enum ServerFinalBody {
    Error(String),
    Verifier(String),
}

/// Model of the final message received from the server.
///
/// MUST validate that this message before auth can be completed.
struct ServerFinal {
    message: String,
    body: ServerFinalBody,
}

impl ServerFinal {
    fn parse(message: &str) -> Result<Self> {
        if message.is_empty() {
            bail!(ErrorKind::AuthenticationError("asdf".to_string()))
        }

        let first = message.chars().nth(0).unwrap();
        let body = if first == ERROR_KEY {
            let error = parse_kvp(message, ERROR_KEY)?;
            ServerFinalBody::Error(error)
        } else if first == VERIFIER_KEY {
            let verifier = parse_kvp(message, VERIFIER_KEY)?;
            ServerFinalBody::Verifier(verifier)
        } else {
            bail!(ErrorKind::AuthenticationError("asd".to_string()))
        };

        Ok(ServerFinal {
            message: message.to_string(),
            body,
        })
    }

    fn validate(
        &self,
        salted_password: &str,
        client_final: &ClientFinal,
        scram: &ScramVersion,
    ) -> Result<()> {
        match &self.body {
            ServerFinalBody::Verifier(body) => {
                let server_key = hmac(salted_password.as_bytes(), "Server Key".as_bytes(), scram);
                let server_signature = hmac(
                    server_key.as_slice(),
                    client_final.auth_message().as_bytes(),
                    scram,
                );
                if base64::encode(server_signature.as_slice()).as_str() == body {
                    Ok(())
                } else {
                    Err(ErrorKind::AuthenticationError("asdf".to_string()).into())
                }
            }
            ServerFinalBody::Error(err) => Err(ErrorKind::AuthenticationError(err.clone()).into()),
        }
    }
}

/// Parses a string slice of the form "<expected_key>=<body>" into "<body>", if possible.
fn parse_kvp(str: &str, expected_key: char) -> Result<String> {
    if str.chars().nth(0) != Some(expected_key) || str.chars().nth(1) != Some('=') {
        bail!(ErrorKind::AuthenticationError("bad format".to_string()))
    };
    Ok(str.chars().skip(2).collect())
}

/// Gets the salted password. Will first check for cached credentials and return those if possible.
/// Updates the cache to store any computed credentials.
fn salted_password(
    credential: &MongoCredential,
    server_first: &ServerFirst,
    scram: &ScramVersion,
) -> Vec<u8> {
    // TODO: check for cached credentials here
    let mut md5 = Md5::new();
    md5.input(format!(
        "{}:mongo:{}",
        credential.username(),
        credential.password().unwrap()
    ));
    let hashed_password = hex::encode(md5.result());
    h_i(
        hashed_password.as_str(),
        server_first.salt(),
        server_first.i(),
        scram,
    )
}

fn authenticate_connection(
    connection: &mut Connection,
    credential: &MongoCredential,
) -> Result<()> {
    let mechanism = credential
        .mechanism()
        .ok_or::<Error>(ErrorKind::AuthenticationError("Missing mechanism".to_string()).into())?;

    let scram = match mechanism {
        AuthMechanism::SCRAMSHA1 => ScramVersion::SHA1,
    };

    if credential.password().is_none() {
        bail!(ErrorKind::AuthenticationError(
            "No password supplied for SCRAM-SHA-1".to_string()
        ))
    };

    if credential.mechanism_properties().is_some() {
        bail!(ErrorKind::AuthenticationError(
            "Mechanism properties MUST NOT be specified for SCRAM-SHA-1".to_string()
        ))
    }

    let nonce = auth::generate_nonce();

    let client_first = ClientFirst::new(credential.username.as_str(), nonce.as_str());
    connection.write(client_first.message().as_bytes())?;

    let mut server_first_string = String::new();
    connection.read_to_string(&mut server_first_string)?;
    let server_first = ServerFirst::parse(server_first_string.as_str())?;
    server_first.validate(nonce.as_str())?;

    let salted_password = salted_password(credential, &server_first, &scram);

    let client_final = ClientFinal::new(
        salted_password.as_slice(),
        &client_first,
        &server_first,
        &scram,
    );
    client_final.message();

    let mut server_final_string = String::new();
    connection.read_to_string(&mut server_final_string)?;

    let server_final = ServerFinal::parse(server_final_string.as_str())?;
    server_final.validate(
        str::from_utf8(salted_password.as_slice()).unwrap(),
        &client_final,
        &scram,
    );

    Ok(())
}
