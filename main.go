/*
* GiantStepsNet - a jazzy protocol parser in GO
* @author - Michele Campus (michelecampus5@gmail.com)
* NOTE: WORK IN PROGRESS
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type GlobalStats struct {
	totNum       uint64
	arpCount     uint64
	sllCount     uint64
	ethCount     uint64
	dnsCount     uint64
	ip4Count     uint64
	ip6Count     uint64
	tcpCount     uint64
	sctpCount    uint64
	udpCount     uint64
	unknownCount uint64
}

type PKTInfo struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	TypeIP    uint8
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      int64
	Tmsec     int64
	Vlan      bool
	VlanVal   uint16
	VxLAN     bool
	VNI       uint32
	GRE       bool
	GREType   uint
	ProtoType byte
	Payload   []byte
}

// For each packet we use again these
var eth layers.Ethernet
var sll layers.LinuxSLL
var arp layers.ARP
var dns layers.DNS
var ipv4 layers.IPv4
var ipv6 layers.IPv6
var tcp layers.TCP
var udp layers.UDP
var sctp layers.SCTP
var gre layers.GRE
var erspan layers.ERSPANII
var vlan layers.Dot1Q
var vxlan layers.VXLAN
var payload gopacket.Payload

var iface *string = flag.String("i", "eth0", "Network interface")
var fname *string = flag.String("p", "", "Pcap file to import")
var snaplen *int = flag.Int("snaplen", 3200, "Snapshot length")
var bpf *string = flag.String("bpf", "", "Berkley Packet Filtering (BPF)")
var promisc *bool = flag.Bool("pmsc", true, "Promiscuos mode")
var dev *bool = flag.Bool("dev", false, "list of availlable network devices")
var debug *bool = flag.Bool("debug", false, "debug level enabled")

func main() {
	programName := "GiantStepsNet"
	//argLen := len(os.Args[1:])

	var err error
	var handle *pcap.Handle
	var pktinfo *PKTInfo          // PACKET INFO
	globalStats := &GlobalStats{} // GLOBAL STATS

	flag.Parse()
	defer handle.Close()

	fmt.Println(":: WELCOME TO", programName, "::")

	/* Print list of availlable devices */
	if *dev {
		ListDevices()
		os.Exit(0)
	}

	/* PCAP or LIVE CAPTURE */
	if *fname != "" {
		fmt.Println("Reading from pcap -->", fname)
		handle, err = pcap.OpenOffline(*fname)
		if err != nil {
			fmt.Fprintf(os.Stderr, ":: ERROR on pcap.OpenOffline --> %s\n", err)
			os.Exit(-1)
		}
	} else {
		fmt.Println("Starting capture on interface -->", iface)
		snap32 := *((*int32)(unsafe.Pointer(snaplen)))
		handle, err = pcap.OpenLive(*iface, snap32, *promisc, pcap.BlockForever)
		if err != nil {
			fmt.Fprintf(os.Stderr, ":: ERROR on pcap.OpenLive --> %s\n", err)
			os.Exit(-1)
		}
	}

	/* Creating log file */
	if _, err := os.Stat("GiantLog.txt"); err != nil { // if does not exists
		if os.IsNotExist(err) {
			fmt.Println("LOG File doesnt exists - Creating new one")
			logfile, err := os.Create("GiantLog.txt")
			fmt.Println("--> Creating LOG file", logfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "::ERR:: Create file ERROR --> %s\n", err)
				return
			}
		}
	}

	// Set BPF filter
	err = handle.SetBPFFilter(*bpf)
	if err != nil {
		fmt.Printf("BPF filter set: [%s]'\n", *bpf)
		log.Fatal(err)
	}

	i := 0
	// METHOD 1. Use the handle as a packet source to process all packets
	packetBegin := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetBegin.Packets() {
		if packet == nil {
			fmt.Println("END OF FILE PCAP")
			break
		}
		// Process packet here
		pktinfo = parsePacketFunc(packet, globalStats, *debug)
		fmt.Println(pktinfo)
		i++
		fmt.Println("i =", i)

	}
	//fmt.Println(globalStats)
}

/* PACKET PARSING */
func parsePacketFunc(packet gopacket.Packet, gstats *GlobalStats, debug bool) *PKTInfo {

	var pktinfo *PKTInfo
	var dataOffset byte
	var greOffset byte
	var data []byte
	var c int8

	pktinfo = &PKTInfo{} // initialize pktinfo struct to be returned
	// Timestamp
	t := time.Now()
	pktinfo.Tsec = t.Unix()
	tUnixMilli := int64(time.Nanosecond) * t.UnixNano() / int64(time.Millisecond)
	pktinfo.Tmsec = tUnixMilli

	// check which packet we're processing
	parser := gopacket.NewDecodingLayerParser(
		packet.LinkLayer().LayerType(),
		&eth, &sll, &arp, &dns, &ipv4, &ipv6, &tcp, &udp,
		&sctp, &gre, &erspan, &vxlan, &vlan, &payload,
	)
	foundLayerTypes := []gopacket.LayerType{} // array layers discovered
	data = packet.Data()
	err := parser.DecodeLayers(data, &foundLayerTypes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding layers: %s\n", err)
	}

	if debug {
		// Iterate over all layers, printing out each layer type
		fmt.Println("ALL packet layers:")
		for _, layer := range packet.Layers() {
			fmt.Println("# ", layer.LayerType())
		}
	}

	// Counter for processing pkts
	gstats.totNum++

	/** Parse layers **/

	// Datalink layer - Ethernet
dl:
	c++
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		pktinfo.SrcMAC = ethernetPacket.SrcMAC
		pktinfo.DstMAC = ethernetPacket.DstMAC
		//Check Ethernet Type to decode tunnelings
		ethType := ethernetPacket.EthernetType
		switch ethType {
		case 0x8100: // vlan
			dataOffset += 4 // bytes
			// TODO other tunnels
		}
		dataOffset += 14
		//fmt.Printf("%+v\n\n", ethernetPacket)
		// Info for global stats
		if c == 1 {
			gstats.ethCount++
		}
	}
	// Datalink layer - Linux Cooked Capture
	sll := packet.Layer(gopacket.LayerType(layers.LinkTypeLinuxSLL))
	if sll != nil {
		sllPacket, _ := sll.(*layers.LinuxSLL)
		pktinfo.SrcMAC = sllPacket.Addr
		//Check Ethernet Type to decode tunnelings
		sslType := sllPacket.EthernetType
		switch sslType {
		case 0x8100: // vlan
			dataOffset += 4 // bytes
			// TODO other tunnels
		default:
		}
		dataOffset += 16
		//fmt.Printf("%+v\n\n", sllPacket)
		// Info for global stats
		if c == 1 {
			gstats.sllCount++
		}
	}

	// IPv4 layer parsing
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ipLen := ip.IHL * 4
		protoType := ip.Protocol
		fmt.Println("protoType = ", protoType)
		switch protoType {
		case 0x2f: // GRE
			data := packet.Data() // data is the beginning of GRE layer
			if data[dataOffset+ipLen+2] == 0x88 && data[dataOffset+ipLen+3] == 0xbe {
				fmt.Println("HERE 1")
				greOffset += dataOffset + ipLen + 8 + 8
			} else if data[dataOffset+ipLen+2] == 0x22 && data[dataOffset+ipLen+3] == 0xeb {
				fmt.Println("HERE 2")
				greOffset += dataOffset + ipLen + 12
			} else {
				fmt.Println("HERE 3")
				greOffset += dataOffset + ipLen + 4
			}
			dataOffset = greOffset
			fmt.Println("GRE OFFSET =", greOffset)
			fmt.Println("DATA OFFSET =", dataOffset)
			// call again to parse the inner packet
			parser.DecodeLayers(data[dataOffset:], &foundLayerTypes)
			fmt.Println("ALL packet layers:")
			for _, layer := range packet.Layers() {
				fmt.Println("# ", layer.LayerType())
			}
			goto dl
		default:
			fmt.Println("NOW HERE")
		}
		//fmt.Printf("%+v\n\n", ip)
	}

	// // Transport layer parsing
	// /// TCP
	// tcpLayer := packet.Layer(layers.LayerTypeTCP)
	// if tcpLayer != nil {
	// 	fmt.Println("[TRNSP layer] TCP layer detected.")
	// 	tcp, _ := tcpLayer.(*layers.TCP)

	// 	/* TCP layer variables:
	// 	* SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
	// 	* Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	// 	 */
	// 	fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
	// 	fmt.Printf("-- SRC PORT = %s\n", tcp.SrcPort)
	// 	fmt.Printf("-- DST PORT = %s\n", tcp.DstPort)
	// 	fmt.Println("-- FLOW : ", tcp.TransportFlow())
	// 	fmt.Println("-- SYN: ", tcp.SYN)
	// 	fmt.Println("-- Seq Number: ", tcp.Seq)
	// 	fmt.Println()
	// 	// TODO extract info for stats
	// }
	// /// UDP
	// udpLayer := packet.Layer(layers.LayerTypeUDP)
	// if udpLayer != nil {
	// 	fmt.Println("[TRNSP layer] UDP layer detected.")
	// 	udp, _ := tcpLayer.(*layers.UDP)

	// 	/* UDP layer variables:
	// 	* TODO
	// 	 */
	// 	fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
	// 	fmt.Printf("-- SRC PORT = %s\n", udp.SrcPort)
	// 	fmt.Printf("-- DST PORT = %s\n", udp.DstPort)
	// 	fmt.Println("-- FLOW : ", udp.TransportFlow())
	// 	fmt.Println("-- Len = ", udp.Length)
	// 	fmt.Println()
	// 	// TODO extract info for stats
	// }

	// /* Application layer parsing - PAYLOAD */
	// payload := packet.ApplicationLayer()
	// if payload != nil {
	// 	fmt.Println("Application layer/Payload found.")
	// 	fmt.Printf("%s\n", payload.Payload())

	// 	/* TODO create dissectors to call here */

	// 	// Search for a string inside the payload
	// 	if strings.Contains(string(payload.Payload()), "ssh") {
	// 		fmt.Println("SSH found!")
	// 	}
	// }

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	return pktinfo
}

/*** AUX FUNC ***/

// ListDevices - find devices and print informations
func ListDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	// Print device information
	fmt.Println("-- Devices --")
	for _, device := range devices {
		if device.Name != "" {
			fmt.Println("\nName: ", device.Name)
		}
		for _, address := range device.Addresses {
			if address.IP != nil {
				fmt.Println("- IP address: ", address.IP)
			}
			if address.Netmask != nil {
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
		}
	}
}
