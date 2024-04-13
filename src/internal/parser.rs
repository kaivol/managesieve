use std::num::NonZeroUsize;
use std::ops::Not;
use std::str::FromStr;

use ascii::Caseless;
use either::Either;
use winnow::ascii::{alpha0, alphanumeric0, crlf, digit1, escaped_transform, space1};
use winnow::binary::{length_take};
use winnow::combinator::{alt, cut_err, opt, repeat};
use winnow::combinator::{delimited, preceded, separated_pair, terminated};
use winnow::error::{
    ContextError, ErrMode, ErrorKind, Needed, ParseError, ParserError, StrContext,
};
use winnow::token::{literal, take_while};
use winnow::{ascii, IResult, PResult, Parser, Partial};

type Input<'a, 'b> = &'a mut Partial<&'b str>;
pub type ParseResult<T> = PResult<T, ErrMode<ContextError>>;

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

impl Response {
    pub const fn new(tag: OkNoBye) -> Response {
        Self {
            tag,
            code: None,
            human: None,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Version {
    major: u64,
    minor: u64,
}

#[derive(Debug, PartialEq, Clone)]
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

macro_rules! assert_parse_success {
    ($parser:path, $input:literal) => {
        let mut input = Partial::new($input);
        $parser(&mut input).unwrap();
    };
    ($parser:path, $input:literal, $result:expr) => {
        assert_parse_success!($parser, $input, $result, "")
    };
    ($parser:path, $input:literal, $result:expr, $rest:literal) => {
        let mut input = Partial::new($input);
        assert_eq!($parser(&mut input), Ok($result));
        assert_eq!(input, Partial::new($rest));
    };
}

macro_rules! assert_parse_incomplete {
    ($parser:path, $input:literal, $result:literal) => {
        assert_parse_incomplete!(inner; $parser, $input, Needed::Size(NonZeroUsize::new($result).unwrap()));
    };
    ($parser:path, $input:literal, $result:expr) => {
        assert_parse_incomplete!(inner; $parser, $input, $result);
    };
    (inner; $parser:path, $input:literal, $result:expr) => {
        let mut input = Partial::new($input);
        assert_eq!($parser(&mut input), Err(ErrMode::Incomplete($result)));
    };
}

macro_rules! assert_parse_error {
    ($parser:path, $input:literal) => {
        let mut input = Partial::new($input);
        assert!(matches!($parser(&mut input), Err(ErrMode::Cut(_) | ErrMode::Backtrack(_))));
    };
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

pub(crate) fn ok(input: Input) -> ParseResult<OkNoBye> {
    Caseless("OK").value(OkNoBye::Ok).parse_next(input)
}

pub(crate) fn no(input: Input) -> ParseResult<OkNoBye> {
    Caseless("NO").value(OkNoBye::No).parse_next(input)
}

pub(crate) fn bye(input: Input) -> ParseResult<OkNoBye> {
    Caseless("BYE").value(OkNoBye::Bye).parse_next(input)
}

pub(crate) fn nobye(input: Input) -> ParseResult<OkNoBye> {
    alt((no, bye)).parse_next(input)
}

fn atom(input: Input) -> ParseResult<ResponseCode> {
    alt((
        Caseless("AUTH-TOO-WEAK").value(ResponseCode::AuthTooWeak),
        Caseless("ENCRYPT-NEEDED").value(ResponseCode::EncryptNeeded),
        Caseless("QUOTA/MAXSCRIPTS").value(ResponseCode::Quota(QuotaVariant::MaxScripts)),
        Caseless("QUOTA/MAXSIZE").value(ResponseCode::Quota(QuotaVariant::MaxSize)),
        Caseless("QUOTA").value(ResponseCode::Quota(QuotaVariant::None)),
        Caseless("REFERRAL").value(ResponseCode::Referral(SieveUrl::new())),
        Caseless("SASL").value(ResponseCode::Sasl),
        Caseless("TRANSITION-NEEDED").value(ResponseCode::TransitionNeeded),
        Caseless("TRYLATER").value(ResponseCode::TryLater),
        Caseless("ACTIVE").value(ResponseCode::Active),
        Caseless("NONEXISTENT").value(ResponseCode::Nonexistent),
        Caseless("ALREADYEXISTS").value(ResponseCode::AlreadyExists),
        Caseless("TAG").value(ResponseCode::Tag),
        Caseless("WARNINGS").value(ResponseCode::Warnings),
    ))
    .parse_next(input)
}

#[test]
fn test_atom() {
    assert_parse_success!(atom, "SASL", ResponseCode::Sasl);
    assert_parse_error!(atom, "ABCDE");
}

fn literal_s2c_len(input: Input) -> ParseResult<u64> {
    terminated(delimited("{", digit1.try_map(u64::from_str), "}"), crlf).parse_next(input)
}

#[test]
fn test_literal_s2c_len() {
    assert_parse_success!(literal_s2c_len, "{3}\r\n", 3);
    assert_parse_success!(literal_s2c_len, "{0}\r\n", 0);
    assert_parse_success!(literal_s2c_len, "{3}\r\nab", 3, "ab");
    assert_parse_incomplete!(literal_s2c_len, "{3}", 2);
}

// Needs to return String because quoted_string does too.
fn literal_s2c(input: Input) -> ParseResult<String> {
    length_take(literal_s2c_len).map(ToOwned::to_owned).parse_next(input)
}

#[test]
fn test_literal_s2c() {
    assert_parse_success!(literal_s2c, "{3}\r\nabc", "abc".into());
    assert_parse_success!(literal_s2c, "{0}\r\n", "".into());
    assert_parse_incomplete!(literal_s2c, "{4}\r\nabc", Needed::Unknown);
}

fn sievestring_s2c(input: Input) -> ParseResult<String> {
    alt((literal_s2c, quoted_string)).parse_next(input)
}

#[test]
fn test_sievestring_s2c() {
    assert_parse_success!(sievestring_s2c, "{3}\r\nabc", "abc".into());
    assert_parse_success!(sievestring_s2c, "\"hello\"", "hello".into());
}

fn literal_c2s_len(input: Input) -> ParseResult<u64> {
    terminated(delimited("{", digit1.try_map(u64::from_str), "+}"), crlf).parse_next(input)
}

#[test]
fn test_literal_c2s_len() {
    assert_parse_success!(literal_c2s_len, "{3+}\r\n", 3);
}

fn literal_c2s(input: Input) -> ParseResult<String> {
    length_take(literal_c2s_len).map(ToOwned::to_owned)
        .parse_next(input)
}

#[test]
fn test_literal_c2s() {
    assert_parse_success!(literal_c2s, "{3+}\r\nabc", "abc".into());
    assert_parse_incomplete!(literal_c2s, "{4+}\r\nabc", Needed::Unknown);
}

fn sievestring_c2s(input: Input) -> ParseResult<String> {
    alt((literal_c2s, quoted_string)).parse_next(input)
}

#[test]
fn test_sievestring_c2s() {
    assert_parse_success!(sievestring_c2s, "{3+}\r\nabc", "abc".into());
    assert_parse_success!(sievestring_c2s, "\"hello\"", "hello".into());
    assert_parse_error!(sievestring_c2s, "{a3+}\r\nabc");
}

fn code(input: Input) -> ParseResult<(ResponseCode, Option<String>)> {
    delimited("(", (atom, opt(preceded(space1, sievestring_s2c))), ")").parse_next(input)
}

#[test]
fn test_code() {
    assert_parse_success!(code, "(QUOTA)", (ResponseCode::Quota(QuotaVariant::None), None));
    assert_parse_success!(
        code,
        "(TAG {16}\r\nSTARTTLS-SYNC-42)",
        (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string()))
    );
    assert_parse_success!(
        code,
        "(TAG \"STARTTLS-SYNC-42\")",
        (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string()))
    );
}

fn quoted_string(input: Input) -> ParseResult<String> {
    delimited(
        "\"",
        escaped_transform(
            take_while(0.., |c| c != '\\' && c != '"'),
            '\\',
            alt(("\\".value("\\"), "\"".value("\""))),
        ),
        "\"",
    )
    .parse_next(input)
}

#[test]
fn test_quoted_string() {
    assert_parse_success!(quoted_string, "\"STARTTLSSYNC-42\"", "STARTTLSSYNC-42".into(), "");
    assert_parse_success!(quoted_string, "\"\"", "".into(), "");
    assert_parse_error!(quoted_string, "hello");
}

// pub fn sieve_name_c2s(input: Input) -> ParseResult<String> {
//     sievestring_c2s
//         .try_map(|s| {
//             s.chars()
//                 .any(is_bad_sieve_name_char)
//                 .not()
//                 .then_some(s)
//                 .ok_or(u64::from_str("a").unwrap_err())
//         })
//         .parse_next(input)
// }
//
// #[test]
// fn test_sieve_name_c2s() {
//     assert_parse_success!(sieve_name_c2s, "\"hello\"", "hello".into());
//     assert_parse_success!(sieve_name_c2s, "\"hello\u{1337}\"", "hello\u{1337}".into());
//     assert_parse_success!(sieve_name_c2s, "{3+}\r\nabc", "abc".into());
//     assert_parse_success!(sieve_name_c2s, "\"he\" \x1f", "he".into(), " \x1f");
//     assert_parse_error!(sieve_name_c2s, "\"he\x1f\"");
// }

// pub fn active_sieve_name(input: Input) -> ParseResult<Option<String>> {
//     opt(sieve_name_c2s).parse_next(input)
// }
//
// #[test]
// fn test_active_sieve_name() {
//     assert!(active_sieve_name("hello  ").unwrap().1.is_none());
//     assert!(active_sieve_name("\"hello \" ").unwrap().1.is_some());
//     assert!(active_sieve_name("\"hello\x7f \" ").is_err());
//     assert!(active_sieve_name("\"\"").is_ok());
//     assert!(matches!(active_sieve_name("hello   "), Ok(("hello   ", None))));
//     assert!(matches!(active_sieve_name("   "), Ok((_, None))));
// }

pub fn response_ok(input: Input) -> ParseResult<Response> {
    terminated(
        (ok, opt(preceded(space1, code)), opt(preceded(space1, quoted_string))).map(
            |(_, code, human)| Response {
                tag: OkNoBye::Ok,
                code,
                human,
            },
        ),
        crlf,
    )
    .parse_next(input)
}

pub fn response_nobye(input: Input) -> ParseResult<Response> {
    terminated(
        (nobye, opt(preceded(space1, code)), opt(preceded(space1, quoted_string))).map(
            |(oknobye, code, human)| Response {
                tag: oknobye,
                code,
                human,
            },
        ),
        crlf,
    )
    .parse_next(input)
}

pub fn response_oknobye(input: Input) -> ParseResult<Response> {
    alt((response_ok, response_nobye)).parse_next(input)
}

#[test]
fn test_response() {
    assert_parse_success!(response_oknobye, "ok\r\n");
    assert_parse_success!(response_oknobye, "nO\r\n");
    assert_parse_success!(response_oknobye, "BYE\r\n");
    assert_parse_success!(response_oknobye, "ok (QUOTA)\r\n");
    assert_parse_success!(response_oknobye, "ok (QUOTA) \"hello\"\r\n");
    assert_parse_incomplete!(response_oknobye, "ok", 1);
    assert_parse_error!(response_oknobye, " ok\r\n");
    assert_parse_error!(response_oknobye, "ok (\r\n");
    assert_parse_error!(response_oknobye, "ok (QUOTA\r\n");
    assert_parse_error!(response_oknobye, "ok (QUOTA/)\r\n");
}

pub fn response_getscript(input: Input) -> ParseResult<(Option<String>, Response)> {
    alt((
        separated_pair(sievestring_s2c, crlf, response_ok).map(|(s, r)| (Some(s), r)),
        response_nobye.map(|r| (None, r)),
    ))
    .parse_next(input)
}

#[test]
fn test_response_getscript() {
    assert_parse_success!(response_getscript, "\"hello\"\r\nOK\r\n");
    assert_parse_success!(response_getscript, "NO\r\n");
    assert_parse_error!(response_getscript, "\"hello\"\r\nBYE\r\n");
}

pub fn response_listscripts(input: Input) -> ParseResult<(Vec<(String, bool)>, Response)> {
    (
        repeat(
            0..,
            terminated(
                (sievestring_s2c, opt((space1, Caseless("ACTIVE"))).map(|o| o.is_some())),
                crlf,
            ),
        ),
        response_oknobye,
    )
        .parse_next(input)
}

#[test]
fn test_response_listscripts() {
    assert_parse_success!(
        response_listscripts,
        "\"script1\"\r\n\"script2\"\r\nOK\r\n",
        (
            vec![("script1".into(), false), ("script2".into(), false),],
            Response::new(OkNoBye::Ok)
        )
    );
    assert_parse_success!(
        response_listscripts,
        "\"script1\" ACTIVE\r\n\"script2\"\r\nOK\r\n",
        (
            vec![("script1".into(), true), ("script2".into(), false),],
            Response::new(OkNoBye::Ok)
        )
    );
    assert_parse_success!(
        response_listscripts,
        "\"script1\" active\r\n\"script2\"\r\nOK\r\n",
        (
            vec![("script1".into(), true), ("script2".into(), false),],
            Response::new(OkNoBye::Ok)
        )
    );
    assert_parse_success!(response_listscripts, "OK\r\n", (vec![], Response::new(OkNoBye::Ok)));
    assert_parse_success!(response_listscripts, "BYE\r\n", (vec![], Response::new(OkNoBye::Bye)));
}

fn space_separated_string_s2c(input: Input) -> ParseResult<Vec<String>> {
    sievestring_s2c
        .map(|s| {
            if s.is_empty() {
                vec![]
            } else {
                s.split(' ').map(String::from).collect()
            }
        })
        .parse_next(input)
}

fn space_separated_string_not_empty_s2c(input: Input) -> ParseResult<Vec<String>> {
    sievestring_s2c
        .try_map(|s| {
            if s.is_empty() {
                Err(u8::from_str("").unwrap_err())
                // Err("expected non-empty space-separated string, found empty string")
            } else {
                Ok(s.split(' ').map(String::from).collect())
            }
        })
        .parse_next(input)
}

fn number_string_s2c(input: Input) -> ParseResult<u64> {
    sievestring_s2c.try_map(|s| s.parse::<u64>()).parse_next(input)
}

fn version(input: Input) -> ParseResult<Version> {
    delimited(
        "\"",
        separated_pair(
            digit1.try_map(|s: &str| s.parse::<u64>()),
            ".",
            digit1.try_map(|s: &str| s.parse::<u64>()),
        )
        .map(|(major, minor)| Version { major, minor }),
        "\"",
    )
    .parse_next(input)
}

fn single_capability(input: Input) -> ParseResult<Capability> {
    //TODO capability name as accept literal-s2c
    terminated(
        alt((
            preceded(Caseless("\"IMPLEMENTATION\""), cut_err(preceded(space1, sievestring_s2c)))
                .map(Capability::Implementation),
            preceded(Caseless("\"SASL\""), cut_err(preceded(space1, space_separated_string_s2c)))
                .map(Capability::Sasl),
            preceded(Caseless("\"SIEVE\""), cut_err(preceded(space1, space_separated_string_s2c)))
                .map(Capability::Sieve),
            preceded(Caseless("\"MAXREDIRECTS\""), cut_err(preceded(space1, number_string_s2c)))
                .map(Capability::MaxRedirects),
            preceded(
                Caseless("\"NOTIFY\""),
                cut_err(preceded(space1, space_separated_string_not_empty_s2c)),
            )
            .map(Capability::Notify),
            Caseless("\"STARTTLS\"").value(Capability::StartTls),
            preceded(Caseless("\"LANGUAGE\""), cut_err(preceded(space1, sievestring_s2c)))
                .map(Capability::Language),
            preceded(Caseless("\"VERSION\""), cut_err(preceded(space1, version)))
                .map(Capability::Version),
            preceded(Caseless("\"OWNER\""), cut_err(preceded(space1, sievestring_s2c)))
                .map(Capability::Owner),
            (sievestring_s2c, opt(preceded(space1, sievestring_s2c)))
                .map(|(cap, arg)| Capability::Unknown(cap, arg)),
        )),
        crlf,
    )
    .parse_next(input)
}

#[test]
fn test_single_capability() {
    assert_parse_success!(single_capability, "\"CAPABILITY1\"\r\n");
    assert_parse_success!(single_capability, "\"CAPABILITY2\" \"a b c d e\"\r\n");
    assert_parse_error!(single_capability, "\"CAPABILITY2\" \r\n");
}

pub fn response_capabilities(input: Input) -> ParseResult<(Vec<Capability>, Response)> {
    (repeat(0.., single_capability), response_oknobye).parse_next(input)
}

#[test]
fn test_response_capabilities() {
    // let input = include_str!("test_input/response_capability-1.txt");
    // let error = response_capabilities(input).finish().err().unwrap();
    // eprintln!("{}", error);
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

pub fn response_starttls(input: Input) -> ParseResult<(Vec<Capability>, Response)> {
    alt((
        preceded(response_ok, response_capabilities),
        response_nobye.map(|r| (Vec::new(), r)),
    ))
    .parse_next(input)
}

#[test]
fn test_response_starttls() {
    assert_parse_success!(response_starttls, "OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n");
    assert_parse_success!(response_starttls, "BYE\r\n");
}

/// Server responds to authenticate with either a challenge or a oknobye
/// response.
pub fn response_authenticate_initial(input: Input) -> ParseResult<Either<String, Response>> {
    alt((
        terminated(sievestring_s2c, crlf).map(|s| Either::Left(s)),
        response_nobye.map(|r| Either::Right(r)),
    ))
    .parse_next(input)
}

#[test]
fn test_response_authenticate_initial() {
    assert_parse_success!(response_authenticate_initial, "{4}\r\nabcd\r\n");
    assert_parse_success!(response_authenticate_initial, "BYE\r\n");
}

/// Server responds to client response with oknobye and can also include new
/// capabilities if OK.
pub fn response_authenticate_complete(
    input: Input,
) -> ParseResult<(Option<Vec<Capability>>, Response)> {
    alt((
        (response_ok, opt(response_capabilities)).map(|(a, b)| match b {
            None => (None, a),
            Some((s, r)) => (Some(s), r),
        }),
        response_nobye.map(|r| (None, r)),
    ))
    .parse_next(input)
}

#[test]
fn test_response_authenticate_complete() {
    assert_parse_success!(
        response_authenticate_complete,
        "OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n"
    );
    assert_parse_success!(response_authenticate_complete, "BYE\r\n");
}
