# managesieve

Parsing and generation of 'managesieve' communications protocol (RFC 5804) 
commands and responses.

Also includes a CLI to manage Sieve scripts on a remote server.

Credits for the parsing logic go to [agrover](https://github.com/agrover). 

## Library
[Docs](https://kaivol.github.io/managesieve/managesieve/)

## CLI
The `managesieve` crate exposes the library's functionality in a 
simple CLI application.
Run `managesieve --help` to see how to use the CLI. 

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