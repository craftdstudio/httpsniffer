package sniffer

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

type Transaction struct {
	Request  *http.Request
	Response *http.Response
}

type Listener func(txn *Transaction) (*Transaction, error)
type ErrorHandler func(*Transaction, error)

func defaultErrHandler(txn *Transaction, err error) {
	if txn != nil && txn.Request != nil {
		log.Printf("Got error (%s) while handling %s\n", txn.Request.URL, err)
		return
	}
	log.Println("Got error", err)
}

type Sniffer struct {
	listeners  []Listener
	txnChan    chan *Transaction
	doneChan   chan bool
	errHandler ErrorHandler
	port       int
	device     string
}

const (
	DefaultDevice = "en0"
	DefaultPort   = 80
	SnapLen       = 1600
)

func New(device string, port int) *Sniffer {
	if len(device) <= 0 {
		device = DefaultDevice
	}
	if port <= 0 {
		port = DefaultPort
	}

	s := &Sniffer{
		txnChan:    make(chan *Transaction),
		listeners:  []Listener{},
		port:       port,
		device:     device,
		doneChan:   make(chan bool),
		errHandler: defaultErrHandler,
	}
	return s
}

func (s *Sniffer) Listen() error {
	go s.runner()
	s.run()
	return nil
}

func (s *Sniffer) SetErrorHandler(eh ErrorHandler) {
	s.errHandler = eh
}

func (s *Sniffer) runner() {
	log.Println("waiting for txns")
	for txn := range s.txnChan {
		for _, lsnr := range s.listeners {
			if txn == nil {
				continue
			}
			txn, err := lsnr(txn)
			if err != nil {
				s.errHandler(txn, err)
				break
			}
		}
	}
}

func (s *Sniffer) Close() {
	s.doneChan <- true
}

func (s *Sniffer) Register(lsn Listener) {
	s.listeners = append(s.listeners, lsn)
}

func (s *Sniffer) bpfFilter() string {
	return fmt.Sprintf("tcp and port %d", s.port)
}

func (s *Sniffer) run() {
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	handle, err = pcap.OpenLive(s.device, int32(SnapLen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(s.bpfFilter()); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{txnChan: s.txnChan}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.NewTicker(time.Minute)
forever:
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeTCP {

				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker.C:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		case <-s.doneChan:
			break forever
		}
	}
}
