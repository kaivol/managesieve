use std::collections::HashMap;
use std::str::FromStr;

use either::Either;
use nom::branch::alt;
use nom::bytes::streaming::{escaped_transform, tag, tag_no_case, take};
use nom::character::streaming::{crlf, digit1, none_of, space1};
use nom::combinator::{cut, map, map_res, opt, value};
use nom::error::{make_error, ErrorKind, VerboseError, VerboseErrorKind, context};
use nom::multi::{length_data, many0};
use nom::sequence::{delimited, pair, preceded, separated_pair, terminated, tuple};
use nom::{Finish, IResult};
use nom_supreme::error::ErrorTree;

pub type ParseResult<'a, T> = IResult<&'a str, T, ErrorTree<&'a str>>;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OkNoBye {
    Ok,
    No,
    Bye,
}

impl std::fmt::Display for OkNoBye {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", match self {
            OkNoBye::Ok => "OK",
            OkNoBye::No => "NO",
            OkNoBye::Bye => "BYE",
        })
    }
}

pub type SieveUrl = String;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum QuotaVariant {
    None,
    MaxScripts,
    MaxSize,
}

type SieveString = String;
type HumanReadableString = SieveString;

#[derive(Debug, PartialEq, Clone)]
pub enum ResponseCode {
    AuthTooWeak,
    EncryptNeeded,
    Quota(QuotaVariant),
    Referral(SieveUrl),
    Sasl,
    TransitionNeeded,
    TryLater,
    Active,
    Nonexistent,
    AlreadyExists,
    Tag,
    Warnings,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    pub tag: OkNoBye,
    pub code: Option<(ResponseCode, Option<String>)>,
    pub human: Option<HumanReadableString>,
}

#[derive(Debug, PartialEq)]
pub struct Version {
    major: u64,
    minor: u64,
}

#[derive(Debug, PartialEq)]
pub enum Capability {
    Implementation(String),
    Sasl(Vec<String>),
    Sieve(Vec<String>),
    StartTls,
    MaxRedirects(u64),
    Notify(Vec<String>),
    Language(String),
    Owner(String),
    Version(Version),
    Unknown(String, Option<String>),
}

pub(crate) fn ok(input: &str) -> ParseResult<OkNoBye> {
    value(OkNoBye::Ok, tag_no_case("OK"))(input)
}

pub(crate) fn no(input: &str) -> ParseResult<OkNoBye> {
    value(OkNoBye::No, tag_no_case("NO"))(input)
}

pub(crate) fn bye(input: &str) -> ParseResult<OkNoBye> {
    value(OkNoBye::Bye, tag_no_case("BYE"))(input)
}

pub(crate) fn nobye(input: &str) -> ParseResult<OkNoBye> {
    alt((no, bye))(input)
}

fn atom(input: &str) -> ParseResult<ResponseCode> {
    map(
        alt((
            tag_no_case("AUTH-TOO-WEAK"),
            tag_no_case("ENCRYPT-NEEDED"),
            tag_no_case("QUOTA/MAXSCRIPTS"),
            tag_no_case("QUOTA/MAXSIZE"),
            tag_no_case("QUOTA"),
            tag_no_case("REFERRAL"),
            tag_no_case("SASL"),
            tag_no_case("TRANSITION-NEEDED"),
            tag_no_case("TRYLATER"),
            tag_no_case("ACTIVE"),
            tag_no_case("NONEXISTENT"),
            tag_no_case("ALREADYEXISTS"),
            tag_no_case("TAG"),
            tag_no_case("WARNINGS"),
        )),
        |s| match s {
            "AUTH-TOO-WEAK" => ResponseCode::AuthTooWeak,
            "ENCRYPT-NEEDED" => ResponseCode::EncryptNeeded,
            "QUOTA" => ResponseCode::Quota(QuotaVariant::None),
            "QUOTA/MAXSCRIPTS" => ResponseCode::Quota(QuotaVariant::MaxScripts),
            "QUOTA/MAXSIZE" => ResponseCode::Quota(QuotaVariant::MaxSize),
            "REFERRAL" => ResponseCode::Referral(SieveUrl::new()),
            "SASL" => ResponseCode::Sasl,
            "TRANSITION-NEEDED" => ResponseCode::TransitionNeeded,
            "TRYLATER" => ResponseCode::TryLater,
            "ACTIVE" => ResponseCode::Active,
            "NONEXISTENT" => ResponseCode::Nonexistent,
            "ALREADYEXISTS" => ResponseCode::AlreadyExists,
            "TAG" => ResponseCode::Tag,
            "WARNINGS" => ResponseCode::Warnings,
            _ => unreachable!(),
        },
    )(input)
}

#[test]
fn test_atom() {
    assert!(matches!(atom("SASL"), Ok(("", ResponseCode::Sasl))));
    assert!(matches!(atom("ABCDE"), Err(_)));
}

fn literal_s2c_len(input: &str) -> ParseResult<u64> {
    terminated(
        delimited(tag("{"), map_res(digit1, |s: &str| s.parse::<u64>()), tag("}")),
        crlf,
    )(input)
}

#[test]
fn test_literal_s2c_len() {
    assert!(matches!(literal_s2c_len("{3}\r\n"), Ok(("", 3))));
    assert!(matches!(literal_s2c_len("{0}\r\n"), Ok(("", 0))));
    assert!(matches!(literal_s2c_len("{3}"), Err(_)));
    assert!(matches!(literal_s2c_len("{3}\r\nab"), Ok(("ab", 3))));
}

// Needs to return String because quoted_string does too.
fn literal_s2c(input: &str) -> ParseResult<String> {
    map(length_data(literal_s2c_len), |s| s.to_owned())(input)
}

#[test]
fn test_literal_s2c() {
    assert_eq!(literal_s2c("{3}\r\nabc").unwrap().1, "abc");
    assert!(literal_s2c("{4}\r\nabc").is_err());
    assert!(literal_s2c("{0}\r\n").is_ok());
}

fn sievestring_s2c(input: &str) -> ParseResult<String> {
    alt((literal_s2c, quoted_string))(input)
}

#[test]
fn test_sievestring_s2c() {
    assert_eq!(sievestring_s2c("{3}\r\nabc").unwrap().1, "abc");
    assert_eq!(sievestring_s2c("\"hello\"").unwrap().1, "hello");
}

fn literal_c2s_len(input: &str) -> ParseResult<u64> {
    terminated(
        delimited(
            tag("{"),
            map_res(digit1, |s: &str| s.parse::<u64>()),
            alt((tag("+}"), tag("}"))),
        ),
        crlf,
    )(input)
}

#[test]
fn test_literal_c2s_len() {
    test_literal_s2c_len();
    assert!(matches!(literal_c2s_len("{3+}\r\n"), Ok(("", 3))));
}

fn literal_c2s(input: &str) -> ParseResult<String> {
    map(length_data(literal_c2s_len), |s| s.to_owned())(input)
}

#[test]
fn test_literal_c2s() {
    test_literal_s2c();
    assert_eq!(literal_c2s("{3+}\r\nabc").unwrap().1, "abc");
    assert!(literal_c2s("{4+}\r\nabc").is_err());
}

fn sievestring_c2s(input: &str) -> ParseResult<String> {
    alt((literal_c2s, quoted_string))(input)
}

#[test]
fn test_sievestring_c2s() {
    assert_eq!(sievestring_c2s("{3+}\r\nabc").unwrap().1, "abc");
    assert_eq!(sievestring_c2s("\"hello\"").unwrap().1, "hello");
}

fn code(input: &str) -> ParseResult<(ResponseCode, Option<String>)> {
    delimited(tag("("), pair(atom, opt(preceded(space1, sievestring_s2c))), tag(")"))(input)
}

#[test]
fn test_code() {
    assert!(matches!(
        code("(QUOTA)"),
        Ok(("", (ResponseCode::Quota(QuotaVariant::None), None)))
    ));
    assert_eq!(
        code("(TAG {16}\r\nSTARTTLS-SYNC-42)").unwrap(),
        ("", (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string())))
    );
    assert_eq!(
        code("(TAG \"STARTTLS-SYNC-42\")").unwrap(),
        ("", (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string())))
    );
}

fn quoted_string(input: &str) -> ParseResult<String> {
    let one: usize = 1;
    delimited(tag("\""), escaped_transform(none_of(r#"\""#), '\\', take(one)), tag("\""))(input)
}

#[test]
fn test_quoted_string() {
    quoted_string("\"hello\"").unwrap();
    quoted_string("\"\"").unwrap();
    assert!(quoted_string("hello").is_err());
}

// see section 1.6 of rfc 5804
pub fn is_bad_sieve_name_char(c: char) -> bool {
    match c {
        c if (c <= 0x1f as char) => true,
        c if (c >= 0x7f as char && c <= 0x9f as char) => true,
        c if (c == '\u{2028}' || c == '\u{2029}') => true,
        _ => false,
    }
}

pub fn sieve_name_c2s(input: &str) -> ParseResult<String> {
    match sievestring_c2s(input) {
        Err(e) => Err(e),
        Ok((rest, s)) => match s.chars().find(|c| is_bad_sieve_name_char(*c)) {
            Some(_) => Err(nom::Err::Failure(make_error(input, ErrorKind::Char))),
            None => Ok((rest, s)),
        },
    }
}

#[test]
fn test_sieve_name_c2s() {
    sieve_name_c2s("\"hello\"").unwrap();
    sieve_name_c2s("\"hello\u{1337}\"").unwrap();
    sieve_name_c2s("{3}\r\nabc").unwrap();
    assert!(matches!(sieve_name_c2s("\"he\x1f\""), Err(nom::Err::Failure(_))));
    assert!(matches!(sieve_name_c2s("\"he\" \x1f"), Ok((" \x1f", _))));
}

pub fn active_sieve_name(input: &str) -> ParseResult<Option<String>> {
    opt(sieve_name_c2s)(input)
}

#[test]
fn test_active_sieve_name() {
    assert!(active_sieve_name("hello  ").unwrap().1.is_none());
    assert!(active_sieve_name("\"hello \" ").unwrap().1.is_some());
    assert!(active_sieve_name("\"hello\x7f \" ").is_err());
    assert!(active_sieve_name("\"\"").is_ok());
    assert!(matches!(active_sieve_name("hello   "), Ok(("hello   ", None))));
    assert!(matches!(active_sieve_name("   "), Ok((_, None))));
}

pub fn response_ok(input: &str) -> ParseResult<Response> {
    terminated(
        map(
            tuple((ok, opt(preceded(space1, code)), opt(preceded(space1, quoted_string)))),
            |(_, code, human)| Response {
                tag: OkNoBye::Ok,
                code,
                human,
            },
        ),
        crlf,
    )(input)
}

pub fn response_nobye(input: &str) -> ParseResult<Response> {
    terminated(
        map(
            tuple((nobye, opt(preceded(space1, code)), opt(preceded(space1, quoted_string)))),
            |(oknobye, code, human)| Response {
                tag: oknobye,
                code,
                human,
            },
        ),
        crlf,
    )(input)
}

pub fn response_oknobye(input: &str) -> ParseResult<Response> {
    alt((response_ok, response_nobye))(input)
}

#[test]
fn test_response() {
    response_oknobye("ok\r\n").unwrap();
    response_oknobye("nO\r\n").unwrap();
    response_oknobye("BYE\r\n").unwrap();
    response_oknobye("ok (QUOTA)\r\n").unwrap();
    response_oknobye("ok (QUOTA) \"hello\"\r\n").unwrap();
    assert!(matches!(response_oknobye("ok"), Err(_)));
    assert!(matches!(response_oknobye(" ok\r\n"), Err(_)));
    assert!(matches!(response_oknobye("ok (\r\n"), Err(_)));
    assert!(matches!(response_oknobye("ok (QUOTA\r\n"), Err(_)));
    assert!(matches!(response_oknobye("ok (QUOTA/)\r\n"), Err(_)));
}

pub fn response_getscript(input: &str) -> ParseResult<(Option<String>, Response)> {
    alt((
        map(separated_pair(sievestring_s2c, crlf, response_ok), |(s, r)| (Some(s), r)),
        map(response_nobye, |r| (None, r)),
    ))(input)
}

#[test]
fn test_response_getscript() {
    response_getscript("\"hello\"\r\nOK\r\n").unwrap();
    response_getscript("NO\r\n").unwrap();
    assert!(matches!(response_getscript("\"hello\"\r\nBYE\r\n"), Err(_)));
}

pub fn response_listscripts(input: &str) -> ParseResult<(Vec<(String, bool)>, Response)> {
    pair(
        many0(terminated(
            pair(sievestring_s2c, map(opt(pair(space1, tag_no_case("ACTIVE"))), |o| o.is_some())),
            crlf,
        )),
        response_oknobye,
    )(input)
}

#[test]
fn test_response_listscripts() {
    response_listscripts("\"script1\"\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("\"script1\" ACTIVE\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("\"script1\" active\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("OK\r\n").unwrap();
    response_listscripts("BYE\r\n").unwrap();
}

fn space_separated_string_s2c(input: &str) -> ParseResult<Vec<String>> {
    map(sievestring_s2c, |s| {
        if s.is_empty() {
            vec![]
        } else {
            s.split(' ').map(String::from).collect()
        }
    })(input)
}

fn space_separated_string_not_empty_s2c(input: &str) -> ParseResult<Vec<String>> {
    map_res(sievestring_s2c, |s| {
        if s.is_empty() {
            Err("expected non-empty space-separated string, found empty string")
        } else {
            Ok(s.split(' ').map(String::from).collect())
        }
    })(input)
}

fn number_string_s2c(input: &str) -> ParseResult<u64> {
    map_res(sievestring_s2c, |s| s.parse::<u64>())(input)
}

fn version(input: &str) -> ParseResult<Version> {
    delimited(
        tag("\""),
        map(
            separated_pair(
                map_res(digit1, |s: &str| s.parse::<u64>()),
                tag("."),
                map_res(digit1, |s: &str| s.parse::<u64>()),
            ),
            |(major, minor)| Version { major, minor },
        ),
        tag("\""),
    )(input)
}

fn single_capability(input: &str) -> ParseResult<Capability> {
    terminated(
        alt((
            //TODO capability name as accept literal-s2c
            map(
                preceded(tag_no_case("\"IMPLEMENTATION\""), cut(preceded(space1, sievestring_s2c))),
                Capability::Implementation,
            ),
            map(
                preceded(
                    tag_no_case("\"SASL\""),
                    cut(preceded(space1, space_separated_string_s2c)),
                ),
                Capability::Sasl,
            ),
            map(
                preceded(
                    tag_no_case("\"SIEVE\""),
                    cut(preceded(space1, space_separated_string_s2c)),
                ),
                Capability::Sieve,
            ),
            map(
                preceded(tag_no_case("\"MAXREDIRECTS\""), cut(preceded(space1, number_string_s2c))),
                Capability::MaxRedirects,
            ),
            map(
                preceded(
                    tag_no_case("\"NOTIFY\""),
                    cut(preceded(space1, space_separated_string_not_empty_s2c)),
                ),
                Capability::Notify,
            ),
            map(tag_no_case("\"STARTTLS\""), |_| Capability::StartTls),
            map(
                preceded(tag_no_case("\"LANGUAGE\""), cut(preceded(space1, sievestring_s2c))),
                Capability::Language,
            ),
            map(
                preceded(tag_no_case("\"VERSION\""), cut(preceded(space1, version))),
                Capability::Version,
            ),
            map(
                preceded(tag_no_case("\"OWNER\""), cut(preceded(space1, sievestring_s2c))),
                Capability::Owner,
            ),
            map(pair(sievestring_s2c, opt(preceded(space1, sievestring_s2c))), |(cap, arg)| {
                Capability::Unknown(cap, arg)
            }),
        )),
        crlf,
    )(input)
}

#[test]
fn test_single_capability() {
    single_capability("\"CAPABILITY1\"\r\n").unwrap();
    single_capability("\"CAPABILITY2\" \"a b c d e\"\r\n").unwrap();
    assert!(single_capability("\"CAPABILITY2\" \r\n").is_err());
}

pub fn response_capabilities(input: &str) -> ParseResult<(Vec<Capability>, Response)> {
    pair(many0(single_capability), response_oknobye)(input)
}

#[test]
fn test_response_capabilities() {
    let input = include_str!("test_input/response_capability-1.txt");
    let error = response_capabilities(input).finish().err().unwrap();
    eprintln!("{}", error);
    // assert_eq!(
    //     response_capabilities(input),
    //     Ok((
    //         "",
    //         (
    //             vec![
    //                 Capability::Implementation("Dovecot Pigeonhole".into()),
    //                 Capability::Sieve(vec![
    //                     "fileinto".into(),
    //                     "reject".into(),
    //                     "envelope".into(),
    //                     "encoded-character".into(),
    //                     "vacation".into(),
    //                     "subaddress".into(),
    //                     "comparator-i;ascii-numeric".into(),
    //                     "relational".into(),
    //                     "regex".into(),
    //                     "imap4flags".into(),
    //                     "copy".into(),
    //                     "include".into(),
    //                     "variables".into(),
    //                     "body".into(),
    //                     "enotify".into(),
    //                     "environment".into(),
    //                     "mailbox".into(),
    //                     "date".into(),
    //                 ]),
    //                 Capability::Notify(vec!["mailto".into()]),
    //                 Capability::Sasl(vec![]),
    //                 Capability::MaxRedirects(42),
    //                 Capability::StartTls,
    //                 Capability::Version(Version { major: 1, minor: 0 }),
    //             ],
    //             Response {
    //                 tag: OkNoBye::Ok,
    //                 code: None,
    //                 human: Some("Dovecot ready.".into()),
    //             }
    //         )
    //     ))
    // );
}

pub fn response_starttls(input: &str) -> ParseResult<(Vec<Capability>, Response)> {
    alt((
        preceded(response_ok, response_capabilities),
        map(response_nobye, |r| (Vec::new(), r)),
    ))(input)
}

#[test]
fn test_response_starttls() {
    response_starttls("OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
    response_starttls("BYE\r\n").unwrap();
}

/// Server responds to authenticate with either a challenge or a oknobye
/// response.
pub fn response_authenticate_initial(input: &str) -> ParseResult<Either<String, Response>> {
    alt((
        map(terminated(sievestring_s2c, crlf), |s| Either::Left(s)),
        map(response_nobye, |r| Either::Right(r)),
    ))(input)
}

#[test]
fn test_response_authenticate_initial() {
    response_authenticate_initial("{4}\r\nabcd\r\n").unwrap();
    response_authenticate_initial("BYE\r\n").unwrap();
}

/// Server responds to client response with oknobye and can also include new
/// capabilities if OK.
pub fn response_authenticate_complete(
    input: &str,
) -> ParseResult<(Option<Vec<Capability>>, Response)> {
    alt((
        map(pair(response_ok, opt(response_capabilities)), |(a, b)| match b {
            None => (None, a),
            Some((s, r)) => (Some(s), r),
        }),
        map(response_nobye, |r| (None, r)),
    ))(input)
}

#[test]
fn test_response_authenticate_complete() {
    response_authenticate_complete("OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
    response_authenticate_complete("BYE\r\n").unwrap();
}
