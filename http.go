package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	reqRes         *Map
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		reqRes:    reqRes,
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
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
			log.Println("request was for", req.Host)
			resp, err := http.ReadResponse(buf, req)
			if err == io.EOF {
				return
			} else if err != nil {
				log.Println(err)
			} else {
				defer resp.Body.Close()
				log.Println("===========RESP============")
				io.Copy(os.Stdout, resp.Body)
				log.Println("===========END RESP============")
			}
		case Req:
			req, err := http.ReadRequest(buf)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("got request", req)
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
