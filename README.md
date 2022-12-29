# httpsniffer
A work-in-progress framework to build HTTP-based sniffers in an easy way. Just register your handlers and it handles everything for you as simple as creating an HTTP Server.

It builds on the battle-hardened [gopacket](https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go), and it adds support for parsing HTTP requests and responses using [net/http](https://pkg.go.dev/net/http).




### Quick Example
```go

func main() {
    sniffer := New()
    sniffer.Register(func(txn *Transaction) (*Transaction, error) {
        fmt.Println(txn.Request)
        fmt.Println(txn.Response)
        return txn, nil
    })
}

```