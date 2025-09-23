package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/viper"
)

// ───────────────────────────────
// IPFIX & Flow Data Structures
// ───────────────────────────────
type MessageHeader struct {
	Version        uint16
	Length         uint16
	ExportTime     uint32
	SequenceNumber uint32
	DomainID       uint32
}

type TemplateHeader struct {
	TemplateID uint16
	FieldCount uint16
}

type TemplateFieldSpecifier struct {
	FieldType uint16
	FieldLen  uint16
}

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// This struct holds the information for a single event
// We no longer aggregate bytes/packets

type SessionEvent struct {
	Key         FlowKey
	EventType   string // e.g., "start", "end"
	ProcessName string
	Timestamp   time.Time
}

var (
	eventBuffer = make([]SessionEvent, 0, 100)
	bufferLock  = &sync.Mutex{}
)

// ───────────────────────────────
// Utils
// ───────────────────────────────
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// ───────────────────────────────
// IPFIX Serialization (Event Based)
// ───────────────────────────────
const (
	eventTypeFieldID   = 34001
	processNameFieldID = 34000
)

func createTemplateSet(templateID uint16) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(2)) // FlowSet ID
	lenPos := buf.Len()
	binary.Write(buf, binary.BigEndian, uint16(0)) // Length placeholder

	binary.Write(buf, binary.BigEndian, templateID)
	binary.Write(buf, binary.BigEndian, uint16(8)) // Field Count: 5-tuple + timestamp + eventType + processName

	fields := []TemplateFieldSpecifier{
		{8, 4},    // sourceIPv4Address
		{12, 4},   // destinationIPv4Address
		{7, 2},    // sourceTransportPort
		{11, 2},   // destinationTransportPort
		{4, 1},    // protocolIdentifier
		{150, 4},  // flowStartSeconds (we'll use this for event time)
		{eventTypeFieldID, 0xFFFF},   // eventType (variable length)
		{processNameFieldID, 0xFFFF}, // processName (variable length)
	}
	for _, f := range fields {
		binary.Write(buf, binary.BigEndian, f.FieldType)
		binary.Write(buf, binary.BigEndian, f.FieldLen)
	}

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[lenPos:], uint16(len(data)))
	return data
}

func serializeDataRecord(event SessionEvent) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, ipToUint32(event.Key.SrcIP))
	binary.Write(buf, binary.BigEndian, ipToUint32(event.Key.DstIP))
	binary.Write(buf, binary.BigEndian, event.Key.SrcPort)
	binary.Write(buf, binary.BigEndian, event.Key.DstPort)
	buf.WriteByte(event.Key.Proto)
	binary.Write(buf, binary.BigEndian, uint32(event.Timestamp.Unix()))

	// Variable length string for event type
	eventBytes := []byte(event.EventType)
	buf.WriteByte(byte(len(eventBytes)))
	buf.Write(eventBytes)

	// Variable length string for process name
	nameBytes := []byte(event.ProcessName)
	if len(nameBytes) > 250 {
		nameBytes = nameBytes[:250]
	}
	buf.WriteByte(byte(len(nameBytes)))
	buf.Write(nameBytes)

	return buf.Bytes()
}

func createDataSet(templateID uint16, records []SessionEvent) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, templateID)
	lenPos := buf.Len()
	binary.Write(buf, binary.BigEndian, uint16(0)) // Length placeholder

	for _, rec := range records {
		buf.Write(serializeDataRecord(rec))
	}

	// Padding to 4-byte boundary
	padding := (4 - (buf.Len() % 4)) % 4
	if padding > 0 {
		buf.Write(make([]byte, padding))
	}

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[lenPos:], uint16(len(data)))
	return data
}

func createIPFIXMessage(seq uint32, templateID uint16, records []SessionEvent) []byte {
	buf := new(bytes.Buffer)

	header := MessageHeader{
		Version:        10,
		Length:         0, // placeholder
		ExportTime:     uint32(time.Now().Unix()),
		SequenceNumber: seq,
		DomainID:       256,
	}
	binary.Write(buf, binary.BigEndian, header)

	templateSet := createTemplateSet(templateID)
	buf.Write(templateSet)

	dataSet := createDataSet(templateID, records)
	buf.Write(dataSet)

	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return data
}

// ───────────────────────────────
// Collector & Exporter Logic
// ───────────────────────────────
func runCollector(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Collector: Starting to capture session events (SYN/FIN/RST)...")

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		var eventType string
		if tcp.SYN && !tcp.ACK {
			eventType = "start"
		} else if tcp.FIN || tcp.RST {
			eventType = "end"
		} else {
			continue // We only care about start/end packets
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		flowKey := FlowKey{
			SrcIP:   ip.SrcIP.String(),
			DstIP:   ip.DstIP.String(),
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Proto:   uint8(ip.Protocol),
		}

		event := SessionEvent{
			Key:       flowKey,
			EventType: eventType,
			Timestamp: time.Now(),
		}

		bufferLock.Lock()
		eventBuffer = append(eventBuffer, event)
		bufferLock.Unlock()
	}
}

func runExporter(conn *net.UDPConn) {
	exporterInterval := viper.GetInt("exporter.interval_seconds")
	if exporterInterval <= 0 {
		log.Printf("Warning: exporter.interval_seconds is non-positive (%d). Using default of 5 seconds.", exporterInterval)
		exporterInterval = 5
	}
	ticker := time.NewTicker(time.Duration(exporterInterval) * time.Second) // Export more frequently
	defer ticker.Stop()

	seq := uint32(1)
	templateID := uint16(256)
	chunkSize := viper.GetInt("exporter.chunk_size")
	if chunkSize <= 0 {
		log.Printf("Warning: exporter.chunk_size is non-positive (%d). Using default of 20.", chunkSize)
		chunkSize = 20
	}

	log.Printf("Exporter: Starting to export session events every %d seconds...\n", exporterInterval)

	for range ticker.C {
		// Step 1: Get a snapshot of connections for PID lookup
		pidLookup := make(map[string]int32)
		conns, err := psnet.Connections("all")
		if err == nil {
			for _, c := range conns {
				if c.Laddr.IP != "" && c.Laddr.Port != 0 {
					key := fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port)
					pidLookup[key] = c.Pid
				}
			}
		}

		// Step 2: Get events from buffer and enrich them
		bufferLock.Lock()
		eventsToExport := make([]SessionEvent, len(eventBuffer))
		copy(eventsToExport, eventBuffer)
		eventBuffer = eventBuffer[:0] // Clear buffer
		bufferLock.Unlock()

		if len(eventsToExport) == 0 {
			log.Println("Exporter: No new session events to export.")
			continue
		}

		// Enrich with process name
		for i := range eventsToExport {
			ev := &eventsToExport[i]
			ev.ProcessName = "unknown"
			lookupKey := fmt.Sprintf("%s:%d", ev.Key.SrcIP, ev.Key.SrcPort)
			if pid, ok := pidLookup[lookupKey]; ok && pid != 0 {
				if p, err := process.NewProcess(pid); err == nil {
					if name, err := p.Name(); err == nil {
						ev.ProcessName = name
					}
				}
			}
		}

		// Step 3: Chunk and send
		totalEvents := len(eventsToExport)
		numChunks := (totalEvents + chunkSize - 1) / chunkSize
		log.Printf("Exporter: Exporting %d events in %d chunks...\n", totalEvents, numChunks)

		for i := 0; i < totalEvents; i += chunkSize {
			end := i + chunkSize
			if end > totalEvents {
				end = totalEvents
			}
			chunk := eventsToExport[i:end]

			msg := createIPFIXMessage(seq, templateID, chunk)
			seq++

			_, err := conn.Write(msg)
			if err != nil {
				log.Println("Exporter: send error:", err)
			}
		}
	}
}

// ───────────────────────────────
// main()
// ───────────────────────────────
func main() {
	vip := viper.New()
	vip.SetConfigName("config") // name of config file (without extension)
	vip.SetConfigType("yaml")    // REQUIRED if the config file does not have the extension in the name
	vip.AddConfigPath(".")       // path to look for the config file in

	// Set default values
	vip.SetDefault("interface", "any")
	vip.SetDefault("bpf.source_host", "")
	vip.SetDefault("collector.host", "127.0.0.1")
	vip.SetDefault("collector.port", 4739)
	vip.SetDefault("exporter.interval_seconds", 5)
	vip.SetDefault("exporter.chunk_size", 20)

	if err := vip.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("config.yaml not found, using defaults.")
		} else {
			log.Fatalf("Error reading config file, %s", err)
		}
	}
	log.Printf("Viper loaded settings: %+v", vip.AllSettings())

	iface := vip.GetString("interface")
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	// Filter for TCP packets that are either SYN (and not ACK), FIN, or RST
	bpfFilter := "(tcp and (((tcp[13] & 2) != 0 and (tcp[13] & 16) = 0) or ((tcp[13] & 5) != 0)))"
	sourceHost := vip.GetString("bpf.source_host")
	if sourceHost != "" {
		bpfFilter = fmt.Sprintf("src host %s and %s", sourceHost, bpfFilter)
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	collectorHost := vip.GetString("collector.host")
	collectorPort := vip.GetInt("collector.port")
	collectorAddr := fmt.Sprintf("%s:%d", collectorHost, collectorPort)
	collector, err := net.ResolveUDPAddr("udp", collectorAddr)
	if err != nil {
		log.Fatal("Unable to resolve UDP address:", err)
	}
	conn, err := net.DialUDP("udp", nil, collector)
	if err != nil {
		log.Fatal("Unable to dial UDP:", err)
	}
	defer conn.Close()

	go runCollector(handle)
	runExporter(conn)
}
