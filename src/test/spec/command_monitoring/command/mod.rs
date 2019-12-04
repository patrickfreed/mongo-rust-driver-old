use bson::{Bson, Document};
use serde::Deserialize;

use super::CommandMonitoringTestFile;
use crate::{
    options::{Collation, CountOptions},
    test::{run_spec_test, CLIENT, LOCK},
};

#[derive(Debug, Deserialize)]
struct Arguments {
    pub filter: Option<Document>,
    pub skip: Option<i64>,
    pub limit: Option<i64>,
}

#[function_name::named]
fn run_command_test(test_file: CommandMonitoringTestFile) {
    
}

#[test]
fn run() {
    run_spec_test(&["crud", "v1", "read"], run_count_test);
}
