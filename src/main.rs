//! A tool to run iftop in text mode and output periodic summaries

#[macro_use]
extern crate lazy_static;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde_derive::Serialize;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

lazy_static! {
    static ref R_SEPARATOR: Regex = Regex::new(r"^-+$").unwrap();
    static ref R_END: Regex = Regex::new(r"^=+$").unwrap();
    //   1 2605:a601:a9b1:7300:49cf:6e19:9c9b:d2ac  =>         0B       709B       457B     20.3KB
    static ref R_FIRSTLINE: Regex = Regex::new(r"(\d+)\s+(\S+)\s+=>\s+(\S+)B\s+(\S+)B\s+(\S+)B\s+(\S+)B").unwrap();
    //     2606:4700:20::6819:9766                  <=         0B     5.69KB     1.71KB     71.4KB
    static ref R_SECONDLINE: Regex = Regex::new(r"(\S+)\s+<=\s+(\S+)B\s+(\S+)B\s+(\S+)B\s+(\S+)B").unwrap();
}

fn main() {
    let default_args = [
        "-t", // text output
        "-B", // output bytes, not bits
        "-n", // no DNS reverse lookup
        "-o", "40s", // sort by 40s column
        "-s", "40", // gather for 40 seconds and then quit
    ];
    let passed_args: Vec<OsString> = env::args_os().skip(1).collect();

    let iftop_args = passed_args
        .iter()
        .map(|x| x.as_os_str())
        .chain(default_args.iter().map(OsStr::new));
    let iftop = Command::new("/usr/sbin/iftop")
        .stdout(Stdio::piped())
        .args(iftop_args)
        .spawn()
        .unwrap();

    let input = BufReader::new(iftop.stdout.unwrap());
    let mut lines = input.lines().map(Result::unwrap);

    while let Some(r) = timed_parse(&mut lines) {
        println!("{}", serde_json::to_string(&r).unwrap());
    }
}

/// Continually parse an iterator of lines until either a blob of Record is parsed, or
/// we run out of input.
///
/// This can panic if the input is malformed. We don't particularly care.
fn parse_input<S: AsRef<str>, T: Iterator<Item = S>>(lines: &mut T) -> Option<Vec<Record>> {
    let mut state = ParseState::Preamble;
    let mut records: Option<Vec<Record>> = None;

    while let Some(l) = lines.next() {
        state = match state {
            ParseState::Preamble => {
                if R_SEPARATOR.is_match(l.as_ref()) {
                    ParseState::Records(Vec::new())
                } else {
                    state
                }
            }
            ParseState::Records(mut r) => {
                if R_SEPARATOR.is_match(l.as_ref()) {
                    records = Some(r);
                    ParseState::Postamble
                } else if let Some(firstline) = R_FIRSTLINE.captures(l.as_ref()) {
                    let l2 = lines.next().unwrap();
                    if let Some(secondline) = R_SECONDLINE.captures(l2.as_ref()) {
                        let record = Record {
                            rank: firstline.get(1).unwrap().as_str().parse().unwrap(),
                            local_name: firstline.get(2).unwrap().as_str().to_string(),
                            outbound_40s_bytes: firstline.get(5).unwrap().as_str().to_string(),
                            remote_name: secondline.get(1).unwrap().as_str().to_string(),
                            inbound_40s_bytes: secondline.get(4).unwrap().as_str().to_string(),
                        };

                        r.push(record);
                    }
                    ParseState::Records(r)
                } else {
                    panic!("Unrecognized line in records input:\n{}", l.as_ref());
                }
            }
            ParseState::Postamble => {
                if R_END.is_match(l.as_ref()) {
                    break;
                } else {
                    state
                }
            }
        };
    }

    records
}

fn timed_parse<S: AsRef<str>, T: Iterator<Item = S>>(lines: &mut T) -> Option<Output> {
    let start_time = Utc::now();
    let r = parse_input(lines);

    r.map(|records| Output {
        start_time,
        records,
        end_time: Utc::now(),
    })
}

#[test]
fn test_parse_state() {
    let input = include_str!("../test/input1.txt");
    let mut lines = input.lines();
    let r = parse_input(&mut lines).unwrap();
    let output = include_str!("../test/output1.txt").trim();
    assert_eq!(output, serde_json::to_string(&r).unwrap());
}

enum ParseState {
    /// Preamble is before first ------
    Preamble,
    /// Records are until next ------
    Records(Vec<Record>),
    /// Postamble is until ending ======
    Postamble,
}

#[derive(Debug, Serialize)]
struct Record {
    rank: u64,
    local_name: String,
    outbound_40s_bytes: String,
    remote_name: String,
    inbound_40s_bytes: String,
}

#[derive(Debug, Serialize)]
struct Output {
    start_time: DateTime<Utc>,
    records: Vec<Record>,
    end_time: DateTime<Utc>,
}
