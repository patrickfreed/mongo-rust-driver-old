use std::{
    env,
    io::{self, Read, Write},
    net::TcpStream,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use bson::{Bson, Document};
use byteorder::{LittleEndian, WriteBytesExt};
use derivative::Derivative;
use r2d2::{ManageConnection, PooledConnection};
use time::PreciseTime;
use webpki::DNSNameRef;

use crate::{
    client::auth::{scram, AuthMechanism, MongoCredential},
    command_responses::IsMasterCommandResponse,
    error::{Error, ErrorKind, Result},
    options::Host,
    topology::ServerType,
    wire::{new_request_id, Header, OpCode, Query, QueryFlags, Reply},
};

const DEFAULT_POOL_SIZE: u32 = 5;
pub const DRIVER_NAME: &str = "mrd";

pub type Connection = PooledConnection<Connector>;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Pool {
    #[derivative(Debug = "ignore")]
    pool: ::r2d2::Pool<Connector>,
}

impl Pool {
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::new_ret_no_self))]
    pub fn new(
        host: Host,
        max_size: Option<u32>,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        credential: Option<MongoCredential>,
    ) -> Result<Self> {
        let pool = ::r2d2::Pool::builder()
            .max_size(max_size.unwrap_or(DEFAULT_POOL_SIZE))
            .build(Connector {
                host,
                tls_config,
                credential,
            })?;

        Ok(Self { pool })
    }
}

impl Deref for Pool {
    type Target = ::r2d2::Pool<Connector>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

pub struct Connector {
    pub host: Host,
    pub tls_config: Option<Arc<rustls::ClientConfig>>,
    pub credential: Option<MongoCredential>,
}

#[allow(clippy::large_enum_variant)]
pub enum Stream {
    Basic(TcpStream),
    Tls(rustls::StreamOwned<rustls::ClientSession, TcpStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Basic(ref mut s) => s.read(buf),
            Stream::Tls(ref mut s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Basic(ref mut s) => s.write(buf),
            Stream::Tls(ref mut s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Basic(ref mut s) => s.flush(),
            Stream::Tls(ref mut s) => s.flush(),
        }
    }
}

impl Connector {
    fn authenticate_stream<T: Read + Write>(
        &self,
        connection: &mut T,
        credential: &MongoCredential,
    ) -> Result<()> {
        println!("authenticating");

        let mechanism = credential.mechanism().ok_or::<Error>(
            ErrorKind::AuthenticationError("Missing mechanism".to_string()).into(),
        )?;

        match &mechanism {
            AuthMechanism::SCRAMSHA1 => match scram::authenticate_stream(connection, credential) {
                Ok(_) => Ok(()),
                Err(e) => {
                    println!("scram failed: {:?}", e);
                    Err(e)
                }
            },
        }
    }
}
//    /// If credentials are provided, perform an authentication handshake. Otherwise, do nothing.
//    fn auth_handshake(&self, connection: &mut Connection) -> Result<()> {
//        match &self.credential {
//            Some(credential) => match is_master(connection, true, Some(credential.clone())) {
//                Ok(reply) => {
//                    let server_type = ServerType::from_ismaster_response(&reply.command_response);
//                    if !server_type.can_auth() {
//                        return Ok(());
//                    };
//                    let mechanism = credential
//                        .mechanism()
//                        .unwrap_or(AuthMechanism::from_is_master(&reply.command_response));
//                    let full_credential = MongoCredential {
//                        mechanism: Some(mechanism),
//                        ..credential.clone()
//                    };
//                    self.authenticate_stream(connection, &full_credential)
//                }
//                Err(e) => bail!(ErrorKind::AuthenticationError(
//                    "is master failed".to_string()
//                )),
//            },
//            None => Ok(()),
//        }
//    }

impl ManageConnection for Connector {
    type Connection = Stream;
    type Error = Error;

    fn connect(&self) -> Result<Self::Connection> {
        println!("connecting to: {}\n", &self.host.display());

        let socket = TcpStream::connect(&self.host.display())?;
        socket.set_nodelay(true)?;

        let mut stream = match self.tls_config {
            Some(ref cfg) => {
                let name = DNSNameRef::try_from_ascii_str(self.host.hostname()).expect("TODO: fix");
                let session = rustls::ClientSession::new(cfg, name);

                Stream::Tls(rustls::StreamOwned::new(session, socket))
            }
            None => Stream::Basic(socket),
        };

        if let Some(credential) = &self.credential {
            println!("performing auth");

            match is_master_stream(&mut stream, false, Some(credential.clone())) {
                Ok(reply) => {
                    let server_type = ServerType::from_ismaster_response(&reply.command_response);
                    if !server_type.can_auth() {
                        println!("can't auth {:?}", server_type);
                        return Ok(stream);
                    };
                    let mechanism = credential
                        .mechanism()
                        .unwrap_or(AuthMechanism::from_is_master(&reply.command_response));
                    let full_credential = MongoCredential {
                        mechanism: Some(mechanism),
                        ..credential.clone()
                    };
                    self.authenticate_stream(&mut stream, &full_credential)?;
                }
                Err(_) => bail!(ErrorKind::AuthenticationError(
                    "is master failed".to_string()
                )),
            }
        };
        Ok(stream)
    }

    // We purposely do nothing here since `is_valid` is called before a connection is returned from
    // `Pool::get`. We choose not to do the connection handshake here since doing so would make it
    // possible for an implementation change to r2d2 to break the handshake spec semantics.
    fn is_valid(&self, _: &mut Self::Connection) -> Result<()> {
        Ok(())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

pub fn run_command_stream<T: Read + Write>(
    stream: &mut T,
    db: &str,
    doc: Document,
    slave_ok: bool,
) -> Result<Document> {
    let header = Header {
        length: 0,
        request_id: new_request_id(),
        response_to: 0,
        opcode: OpCode::Query,
    };

    let mut flags = QueryFlags::empty();

    if slave_ok {
        flags.insert(QueryFlags::SLAVE_OK);
    }

    let query = Query {
        header,
        flags,
        full_collection_name: format!("{}.$cmd", db),
        num_to_skip: 0,
        num_to_return: 1,
        query: doc,
        return_field_selector: None,
    };

    let mut bytes: Vec<u8> = Vec::new();
    query.write(&mut bytes)?;

    let num_bytes = bytes.len();
    (&mut bytes[0..4]).write_i32::<LittleEndian>(num_bytes as i32)?;

    let _ = stream.write(&bytes[..])?;
    let reply = Reply::read(stream)?;

    match reply.docs.into_iter().next() {
        Some(doc) => Ok(doc),
        None => bail!(ErrorKind::OperationError(
            "The reply from the server did not contain a document".to_string()
        )),
    }
}

pub fn run_command(
    conn: &mut Connection,
    db: &str,
    doc: Document,
    slave_ok: bool,
) -> Result<Document> {
    let header = Header {
        length: 0,
        request_id: new_request_id(),
        response_to: 0,
        opcode: OpCode::Query,
    };

    let mut flags = QueryFlags::empty();

    if slave_ok {
        flags.insert(QueryFlags::SLAVE_OK);
    }

    let query = Query {
        header,
        flags,
        full_collection_name: format!("{}.$cmd", db),
        num_to_skip: 0,
        num_to_return: 1,
        query: doc,
        return_field_selector: None,
    };

    let mut bytes: Vec<u8> = Vec::new();
    query.write(&mut bytes)?;

    let num_bytes = bytes.len();
    (&mut bytes[0..4]).write_i32::<LittleEndian>(num_bytes as i32)?;

    let _ = conn.write(&bytes[..])?;
    let reply = Reply::read(conn.deref_mut())?;

    match reply.docs.into_iter().next() {
        Some(doc) => Ok(doc),
        None => bail!(ErrorKind::OperationError(
            "The reply from the server did not contain a document".to_string()
        )),
    }
}

pub struct IsMasterReply {
    pub command_response: IsMasterCommandResponse,
    pub round_trip_time: i64,
}

pub fn is_master_stream<T: Read + Write>(
    stream: &mut T,
    handshake: bool,
    credential: Option<MongoCredential>,
) -> Result<IsMasterReply> {
    let mut doc = if handshake {
        doc! {
            "isMaster": 1,
            "client": {
                "driver": {
                    "name": DRIVER_NAME,
                    "version": env!("CARGO_PKG_VERSION")
                },
                "os": {
                    "type": env::consts::OS,
                    "architecture": env::consts::ARCH
                }
            }
        }
    } else {
        doc! { "isMaster": 1 }
    };

    if let Some(cred) = credential {
        doc.insert(
            "saslSupportedMechs",
            format!("{}.{}", cred.source(), cred.username()),
        );
    };

    let start = PreciseTime::now();
    let response_doc = run_command_stream(stream, "admin", doc, false)?;
    let round_trip_time = start.to(PreciseTime::now());
    let command_response = bson::from_bson(Bson::Document(response_doc))?;

    Ok(IsMasterReply {
        command_response,
        round_trip_time: round_trip_time.num_milliseconds(),
    })
}

pub fn is_master(
    conn: &mut Connection,
    handshake: bool,
    credential: Option<MongoCredential>,
) -> Result<IsMasterReply> {
    let mut doc = if handshake {
        doc! {
            "isMaster": 1,
            "client": {
                "driver": {
                    "name": DRIVER_NAME,
                    "version": env!("CARGO_PKG_VERSION")
                },
                "os": {
                    "type": env::consts::OS,
                    "architecture": env::consts::ARCH
                }
            }
        }
    } else {
        doc! { "isMaster": 1 }
    };

    if let Some(cred) = credential {
        doc.insert(
            "saslSupportedMechs",
            format!("{}.{}", "admin", cred.username()),
        );
    }

    let start = PreciseTime::now();
    let doc = run_command(conn, "admin", doc, false)?;
    let round_trip_time = start.to(PreciseTime::now());

    let command_response = bson::from_bson(Bson::Document(doc))?;

    Ok(IsMasterReply {
        command_response,
        round_trip_time: round_trip_time.num_milliseconds(),
    })
}
