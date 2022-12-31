# httpsniffer
A work-in-progress framework to build HTTP-based sniffers in an easy way. Just register your handlers and it handles everything for you as simple as creating an HTTP Server.

It builds on the battle-hardened [gopacket](https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go), and it adds support for parsing HTTP requests and responses using [net/http](https://pkg.go.dev/net/http).


**NOTE**: the API is still under heavy development, therefore subject to substantial changes.


### Quick Example
```go

func main() {
    device := "eth0"
    port := 80
    sniffer := New(device, port)

    // you can register as many handlers you want
    // httpsniffer will chain the request through them in the order they were registered
    // the output of each handler will the input of the next handler
    sniffer.Register(func(txn *Transaction) (*Transaction, error) {
        fmt.Println(txn.Request)
        fmt.Println(txn.Response)
        return txn, nil
    })

    // starts the sniffing for HTTP request on device eth0 and port 80
    sniffer.Listen()
}

```