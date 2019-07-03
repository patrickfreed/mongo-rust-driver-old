use std::fmt;

error_chain! {
    foreign_links {
        BsonOid(bson::oid::Error);
        BsonDecode(bson::DecoderError);
        BsonEncode(bson::EncoderError);
        Io(std::io::Error);
        R2D2(r2d2::Error);
    }

    errors {
       /// A malformed or invalid argument was passed to the driver.
        ArgumentError(msg: String) {
            description("An invalid argument was provided to a database operation")
            display("An invalid arugment was provided to a database operation: {}", msg)
        }

        /// The server encountered an error when executing the operation.
        CommandError(code: u32, code_name: String, msg: String, labels: Vec<String>) {
            description("An error occurred when executing a command")
            display("Command failed ({}): {}", code_name, msg)
        }

        /// The driver was unable to send or receive a message to the server.
        InvalidHostname(hostname: String) {
            description("Unable to parse hostname")
            display("Unable to parse hostname: '{}'", hostname)
        }

        OperationError(msg: String) {
            description("A database operation failed to send or receive a reply")
            display("A database operation failed to send or receive a reply: {}", msg)
        }

       /// The response the driver received from the server was not in the form expected.
        ParseError(data_type: String, file_path: String) {
            description("Unable to parse data from file")
            display("Unable to parse {} data from {}", data_type, file_path)
        }

        ResponseError(msg: String) {
            description("A database operation returned an invalid reply")
            display("A database operation returned an invalid reply: {}", msg)
        }

        /// An error occurred during server selection.
        ServerError(operation: String, msg: String) {
            description("An attempted database operation failed")
            display("{} operation failed: {}", operation, msg)
        }

        ServerSelectionError(msg: String) {
            description("An error occurred during server selection")
            display("An error occured during server selection: {}", msg)
        }

        /// An error occurred when trying to execute a write operation.
        WriteError(inner: WriteFailure) {
            description("An error occurred when trying to execute a write operation:")
            display("{}", inner)
        }

        AuthenticationError(msg: String) {
            description("WIP")
            display("WIP")
        }
    }
}

/// An error that occurred due to not being able to satisfy a write concern.
#[derive(Debug)]
pub struct WriteConcernError {
    /// Identifies the type of write concern error.
    pub code: i32,

    /// The name associated with the error code.
    pub code_name: String,

    /// A description of the error that occurred.
    pub message: String,
}

/// An error that occurred duringn a write operation that wasn't due to being unable to satisfy a
/// write concern.
#[derive(Debug)]
pub struct WriteError {
    /// Identifies the type of write concern error.
    pub code: i32,

    /// The name associated with the error code.
    ///
    /// Note that the server will not return this in some cases, hence `code_name` being an
    /// `Option`.
    pub code_name: Option<String>,

    /// A description of the error that occurred.
    pub message: String,
}

/// An error that occurred when trying to execute a write operation.
#[derive(Debug)]
pub enum WriteFailure {
    WriteConcernError(WriteConcernError),
    WriteError(WriteError),
}

impl fmt::Display for WriteFailure {
    fn fmt(&self, _fmt: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}
