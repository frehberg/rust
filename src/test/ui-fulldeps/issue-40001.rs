// run-pass
// aux-build:issue-40001-plugin.rs
// ignore-stage1

#![feature(plugin)]
#![plugin(issue_40001_plugin)] //~ WARNING compiler plugins are deprecated

#[whitelisted_attr]
fn main() {}
