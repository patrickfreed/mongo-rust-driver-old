use std::collections::HashMap;

use bson::{bson, doc, Bson, Document};

use crate::{
    bson_util,
    cmap::{Command, CommandResponse, StreamDescription},
    error::Result,
    operation::{append_options, Operation, WriteResponseBody},
    options::InsertManyOptions,
    results::InsertManyResult,
    Namespace,
};

#[derive(Debug)]
pub(crate) struct Insert {
    ns: Namespace,
    documents: Vec<Document>,
    options: Option<InsertManyOptions>,
}

impl Insert {
    pub(crate) fn new(
        ns: Namespace,
        documents: Vec<Document>,
        options: Option<InsertManyOptions>,
    ) -> Self {
        Self {
            ns,
            options,
            documents: documents
                .into_iter()
                .map(|mut d| {
                    bson_util::add_id(&mut d);
                    d
                })
                .collect(),
        }
    }
}

impl Operation for Insert {
    type O = InsertManyResult;
    const NAME: &'static str = "insert";

    fn build(&self, description: &StreamDescription) -> Result<Command> {
        let mut body = doc! {
            Self::NAME: self.ns.coll.clone(),
            "documents": Bson::Array(self.documents.iter().map(|d| Bson::Document(d.clone())).collect()),
        };
        append_options(&mut body, self.options.as_ref())?;

        Ok(Command::new(
            Self::NAME.to_string(),
            self.ns.db.clone(),
            body,
        ))
    }

    fn handle_response(&self, response: CommandResponse) -> Result<Self::O> {
        let body = response.body::<WriteResponseBody>()?;
        body.validate()?;

        let mut map = HashMap::<usize, Bson>::new();
        for (i, doc) in self.documents.iter().enumerate() {
            map.insert(i, doc.get("_id").unwrap().clone());
        }
        Ok(InsertManyResult { inserted_ids: map })
    }
}

#[cfg(test)]
mod test {
    use bson::{bson, doc, Bson, Document};

    use crate::{
        cmap::{CommandResponse, StreamDescription},
        error::{BulkWriteError, ErrorKind, WriteConcernError},
        operation::{test, Insert, Operation},
        options::InsertManyOptions,
        Namespace,
    };

    /// Get an Insert operation and the documents/options used to construct it.
    fn fixtures() -> (Insert, Vec<Document>, InsertManyOptions) {
        let documents = vec![
            Document::new(),
            doc! {"_id": 1234, "a": 1},
            doc! {"a": 123, "b": "hello world" },
        ];

        let options = InsertManyOptions {
            ordered: Some(true),
            ..Default::default()
        };

        let op = Insert::new(
            Namespace {
                db: "test_db".to_string(),
                coll: "test_coll".to_string(),
            },
            documents.clone(),
            Some(options.clone()),
        );

        (op, documents, options)
    }

    #[test]
    fn build() {
        let (op, documents, options) = fixtures();

        let description = StreamDescription::new_42();
        let cmd = op.build(&description).unwrap();

        assert_eq!(cmd.name.as_str(), "insert");
        assert_eq!(cmd.target_db.as_str(), "test_db");
        assert_eq!(cmd.read_pref.as_ref(), None);

        assert_eq!(
            cmd.body.get("insert").unwrap(),
            &Bson::String("test_coll".to_string())
        );

        let mut cmd_docs: Vec<Document> = cmd
            .body
            .get("documents")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_document().unwrap().clone())
            .collect();
        assert_eq!(cmd_docs.len(), documents.len());

        for (original_doc, cmd_doc) in documents.iter().zip(cmd_docs.iter_mut()) {
            assert!(cmd_doc.get("_id").is_some());
            if original_doc.get("_id").is_some() {
                assert_eq!(original_doc, cmd_doc);
            } else {
                cmd_doc.remove("_id");
                assert_eq!(original_doc, cmd_doc);
            };
        }

        assert_eq!(cmd.body.get("ordered"), Some(&Bson::Boolean(true)));
        assert!(cmd.body.get("bypassDocumentValidation").is_none());
    }

    #[test]
    fn handle_success() {
        let (op, documents, _) = fixtures();

        let ok_response = CommandResponse::from_document(doc! { "ok": 1.0, "n": 3 });
        let ok_result = op.handle_response(ok_response);
        assert!(ok_result.is_ok());

        let inserted_ids = ok_result.unwrap().inserted_ids;
        assert_eq!(inserted_ids.len(), 3); // populate _id for documents that don't provide it
        assert_eq!(
            inserted_ids.get(&1).unwrap(),
            documents[1].get("_id").unwrap()
        );
    }

    #[test]
    fn handle_invalid_response() {
        let (op, ..) = fixtures();

        let invalid_response =
            CommandResponse::from_document(doc! { "ok": 1.0, "asdfadsf": 123123 });
        assert!(op.handle_response(invalid_response).is_err());
    }

    #[test]
    fn handle_command_error() {
        let (op, ..) = fixtures();
        test::handle_command_error(op);
    }

    #[test]
    fn handle_write_failure() {
        let (op, ..) = fixtures();

        let write_error_response = CommandResponse::from_document(doc! {
            "ok": 1.0,
            "n": 1,
            "writeErrors": [
                {
                    "index": 1,
                    "code": 11000,
                    "errmsg": "duplicate key"
                }
            ],
            "writeConcernError": {
                "code": 123,
                "codeName": "woohoo",
                "errmsg": "error message"
            }
        });

        let write_error_result = op.handle_response(write_error_response);
        assert!(write_error_result.is_err());

        match *write_error_result.unwrap_err().kind {
            ErrorKind::BulkWriteError { inner: ref error } => {
                let write_errors = error.write_errors.clone().unwrap();
                assert_eq!(write_errors.len(), 1);
                let expected_err = BulkWriteError {
                    index: 1,
                    code: 11000,
                    code_name: None,
                    message: "duplicate key".to_string(),
                };
                assert_eq!(write_errors.first().unwrap(), &expected_err);

                let write_concern_error = error.write_concern_error.clone().unwrap();
                let expected_wc_err = WriteConcernError {
                    code: 123,
                    code_name: "woohoo".to_string(),
                    message: "error message".to_string(),
                };
                assert_eq!(write_concern_error, expected_wc_err);
            }
            ref e => panic!("expected bulk write error, got {:?}", e),
        };
    }
}
