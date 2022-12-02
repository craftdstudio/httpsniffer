# httpsniffer
A work-in-progress passive HTTP sniffer using BPF.

It builds on the battle-hardened [gopacket](https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go), and it adds support for parsing HTTP requests and responses using [net/http](https://pkg.go.dev/net/http).

### Goals
- Generate OpenAPI specs from network traffic
- Generate telemtry data, a la openTelemtry traces.
- ... generally speaking an automagically tool that gives insights on how your API is performing.

