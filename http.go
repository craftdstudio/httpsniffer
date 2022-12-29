package sniffer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	txnChan chan *Transaction
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	reqRes         *Map
	txnChan        chan *Transaction
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		reqRes:    reqRes,
		txnChan:   h.txnChan,
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	log.Println(h.net.Src())
	log.Println(h.transport.Src())
	// TODO(kl): add state machine to read requests then responses
	for {
		htype, err := h.peek(buf)
		if err != nil {
			return
		}
		switch htype {
		case Res:
			key := genKey(h.net.Reverse(), h.transport.Reverse())
			req, ok := h.reqRes.Get(key)
			if !ok {
				log.Printf("request not found %s\n", key)
			}
			resp, err := http.ReadResponse(buf, req)
			if err == io.EOF {
				return
			} else if err != nil {
				log.Println(err)
			} else {
				txn := &Transaction{
					Request:  req,
					Response: resp,
				}
				// copy the resp body to move the reader position
				if resp.Body != nil {
					// TODO(kl): copy response body to a buffer obtained from a pool
					n, err := io.Copy(io.Discard, resp.Body)
					log.Println(n, err)
					resp.Body.Close()
				}
				h.txnChan <- txn
				// TODO(kl): handle pipelining
				h.reqRes.Delete(key)
			}
		case Req:
			req, err := http.ReadRequest(buf)
			if err != nil {
				log.Println("not able to read request", err)
				continue
			}
			log.Println("got req", req)
			key := genKey(h.net, h.transport)
			h.reqRes.Add(key, req)
		}
	}
}

func genKey(net, transport gopacket.Flow) string {
	return fmt.Sprintf("%s:%s->%s:%s",
		net.Src(), transport.Src(),
		net.Dst(), transport.Dst())
}

type HType int

const (
	Req HType = iota
	Res
	Uknown
)

func (h *httpStream) peek(buf *bufio.Reader) (HType, error) {
	p4, err := buf.Peek(4)
	if err != nil {
		return Uknown, err
	}

	if bytes.Equal(p4, []byte("HTTP")) {
		return Res, nil
	}
	return Req, nil
}
