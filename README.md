# managesieve-client

Sieve scripts allow users to filter incoming email.
This crate implement parsing and generation of "ManageSieve" communication protocol ([RFC 5804](#spec)) commands and responses, to allow communication with sieve servers.


Also includes a [CLI](#cli) to manage Sieve scripts on a remote server.

Credits for the parsing logic go to [agrover](https://github.com/agrover). 

## Library
[Docs](https://kaivol.github.io/managesieve/managesieve_client/)

## CLI
The `sieve-client` binary exposes the library's functionality in a simple CLI application.
Run `sieve-client --help` to see how to use the CLI. 

## TODO
- [ ] Implement missing commands
- [ ] Support SASL security layer
- [ ] CLI
  - [ ] Support all commands

## Spec
Relevant RFC's:

- A Protocol for Remotely Managing Sieve Scripts (ManageSieve)  
  RFC 5804: https://datatracker.ietf.org/doc/html/rfc5804

- Simple Authentication and Security Layer (SASL)  
  RFC 4422: https://datatracker.ietf.org/doc/html/rfc4422