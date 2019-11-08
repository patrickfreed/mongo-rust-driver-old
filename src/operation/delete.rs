use bson::{bson, doc, Document};

use crate::{
    cmap::{Command, CommandResponse, StreamDescription},
    coll::Namespace,
    concern::WriteConcern,
    error::{convert_bulk_errors, Result},
    operation::{append_options, Operation, WriteResponseBody},
    options::DeleteOptions,
    results::DeleteResult,
};

#[derive(Debug)]
pub(crate) struct Delete {
    ns: Namespace,
    filter: Document,
    limit: u32,
    write_concern: Option<WriteConcern>,
    options: Option<DeleteOptions>,
}

impl Delete {
    #[allow(dead_code)]
    fn empty() -> Self {
        Self::new(
            Namespace {
                db: "".to_string(),
                coll: "".to_string(),
            },
            Document::new(),
            None,
            None,
            None,
        )
    }

    pub(crate) fn new(
        ns: Namespace,
        filter: Document,
        limit: Option<u32>,
        coll_write_concern: Option<WriteConcern>,
        options: Option<DeleteOptions>,
    ) -> Self {
        Self {
            ns,
            filter,
            limit: limit.unwrap_or(0),         // 0 = no limit
            write_concern: coll_write_concern, // TODO: RUST-35 check wc from options
            options,
        }
    }
}

impl Operation for Delete {
    type O = DeleteResult;
    const NAME: &'static str = "delete";

    fn build(&self, description: &StreamDescription) -> Result<Command> {
        let mut body = doc! {
            Self::NAME: self.ns.coll.clone(),
            "deletes": [
                {
                    "q": self.filter.clone(),
                    "limit": self.limit,
                }
            ]
        };
        append_options(&mut body, self.options.as_ref())?;

        if let Some(ref write_concern) = self.write_concern {
            body.insert("writeConcern", write_concern.to_bson());
        }

        Ok(Command::new(
            Self::NAME.to_string(),
            self.ns.db.clone(),
            body,
        ))
    }

    fn handle_response(&self, response: CommandResponse) -> Result<Self::O> {
        let body: WriteResponseBody = response.body()?;
        body.validate().map_err(convert_bulk_errors)?;

        Ok(DeleteResult {
            deleted_count: body.n,
        })
    }
}

#[cfg(test)]
mod test {
    use bson::{bson, doc};

    use crate::{
        bson_util,
        cmap::{CommandResponse, StreamDescription},
        concern::{Acknowledgment, WriteConcern},
        error::{ErrorKind, WriteConcernError, WriteError, WriteFailure},
        operation::{test, Delete, Operation},
        Namespace,
    };

    #[test]
    fn build_many() {
        let ns = Namespace {
            db: "test_db".to_string(),
            coll: "test_coll".to_string(),
        };
        let filter = doc! { "x": { "$gt": 1 } };

        let wc = WriteConcern {
            w: Some(Acknowledgment::Majority),
            ..Default::default()
        };

        let op = Delete::new(ns, filter.clone(), None, Some(wc), None);

        let description = StreamDescription::new_testing();
        let mut cmd = op.build(&description).unwrap();

        assert_eq!(cmd.name.as_str(), "delete");
        assert_eq!(cmd.target_db.as_str(), "test_db");
        assert_eq!(cmd.read_pref.as_ref(), None);

        let mut expected_body = doc! {
            "delete": "test_coll",
            "deletes": [
                {
                    "q": filter,
                    "limit": 0,
                }
            ],
            "writeConcern": {
                "w": "majority"
            },
        };

        bson_util::sort_document(&mut cmd.body);
        bson_util::sort_document(&mut expected_body);

        assert_eq!(cmd.body, expected_body);
    }

    #[test]
    fn build_one() {
        let ns = Namespace {
            db: "test_db".to_string(),
            coll: "test_coll".to_string(),
        };
        let filter = doc! { "x": { "$gt": 1 } };

        let wc = WriteConcern {
            w: Some(Acknowledgment::Majority),
            ..Default::default()
        };

        let op = Delete::new(ns, filter.clone(), Some(1), Some(wc), None);

        let description = StreamDescription::new_testing();
        let mut cmd = op.build(&description).unwrap();

        assert_eq!(cmd.name.as_str(), "delete");
        assert_eq!(cmd.target_db.as_str(), "test_db");
        assert_eq!(cmd.read_pref.as_ref(), None);

        let mut expected_body = doc! {
            "delete": "test_coll",
            "deletes": [
                {
                    "q": filter,
                    "limit": 1,
                }
            ],
            "writeConcern": {
                "w": "majority"
            },
        };

        bson_util::sort_document(&mut cmd.body);
        bson_util::sort_document(&mut expected_body);

        assert_eq!(cmd.body, expected_body);
    }

    #[test]
    fn handle_success() {
        let op = Delete::empty();

        let ok_response = CommandResponse::from_document(doc! {
            "ok": 1.0,
            "n": 3,
        });

        let ok_result = op.handle_response(ok_response);
        assert!(ok_result.is_ok());

        let delete_result = ok_result.unwrap();
        assert_eq!(delete_result.deleted_count, 3);
    }

    #[test]
    fn handle_invalid_response() {
        let op = Delete::empty();

        let invalid_response =
            CommandResponse::from_document(doc! { "ok": 1.0, "asdfadsf": 123123 });
        assert!(op.handle_response(invalid_response).is_err());
    }

    #[test]
    fn handle_command_error() {
        test::handle_command_error(Delete::empty())
    }

    #[test]
    fn handle_write_failure() {
        let op = Delete::empty();

        let write_error_response = CommandResponse::from_document(doc! {
            "ok": 1.0,
            "n": 0,
            "writeErrors": [
                {
                    "index": 0,
                    "code": 1234,
                    "errmsg": "my error string"
                }
            ]
        });
        let write_error_result = op.handle_response(write_error_response);
        assert!(write_error_result.is_err());
        match *write_error_result.unwrap_err().kind {
            ErrorKind::WriteError {
                inner: WriteFailure::WriteError(ref error),
            } => {
                let expected_err = WriteError {
                    code: 1234,
                    code_name: None,
                    message: "my error string".to_string(),
                };
                assert_eq!(error, &expected_err);
            }
            ref e => panic!("expected write error, got {:?}", e),
        };
    }

    #[test]
    fn handle_write_concern_failure() {
        let op = Delete::empty();

        let wc_error_response = CommandResponse::from_document(doc! {
            "ok": 1.0,
            "n": 0,
            "writeConcernError": {
                "code": 456,
                "codeName": "wcError",
                "errmsg": "some message"
            }
        });

        let wc_error_result = op.handle_response(wc_error_response);
        assert!(wc_error_result.is_err());

        match *wc_error_result.unwrap_err().kind {
            ErrorKind::WriteError {
                inner: WriteFailure::WriteConcernError(ref wc_error),
            } => {
                let expected_wc_err = WriteConcernError {
                    code: 456,
                    code_name: "wcError".to_string(),
                    message: "some message".to_string(),
                };
                assert_eq!(wc_error, &expected_wc_err);
            }
            ref e => panic!("expected write concern error, got {:?}", e),
        }
    }
}
