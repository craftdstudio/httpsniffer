// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides sample code for using the gopacket TCP assembler and TCP
// stream reader.  It reads packets off the wire and reconstructs HTTP requests
// it sees, logging them.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "en0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and port 80", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

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

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
