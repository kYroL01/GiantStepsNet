/*
* GiantStepsNet - a jazzy protocol parser in GO
* @author - Michele Campus (michelecampus5@gmail.com)
* NOTE: WORK IN PROGRESS
 */

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// For each packet we use again these
var eth layers.Ethernet
var sll layers.LinuxSLL
var ipv4 layers.IPv4
var ipv6 layers.IPv6
var tcp layers.TCP
var udp layers.UDP
var sct layers.SCTP

func main() {
	programName := "GiantStepsNet"
	argLen := len(os.Args[1:])

	var (
		iface   string
		fname   string
		snaplen int32 = 1500
		filter        = "vlan or ip" // BPF filter
		promisc bool  = false
		err     error
		//timeout      time.Duration = 30 * time.Second
		handle *pcap.Handle
	)

	defer handle.Close()

	// check arguments
	if argLen == 0 {
		fmt.Println("Program", programName, "has no argument")
		fmt.Println("Type -h to see options")
		os.Exit(1)
	}
	// parse arguments
	for i := 0; i < argLen; i++ {
		a := os.Args[i+1]
		switch a {
		// -h option
		case "-h":
			Help(programName)
			os.Exit(0)
		case "-l":
			ListDevices()
			os.Exit(0)
		case "-i":
			iface = os.Args[i+2]
			break
		case "-p":
			fname = os.Args[i+2]
			break
		default:
			break
		}
	}

	fmt.Println(":: WELCOME TO", programName, "::")

	/* PCAP or LIVE CAPTURE */
	if fname != "" {
		fmt.Printf("Reading from pcap [%s]\n", fname)
		handle, err = pcap.OpenOffline(fname)
	} else {
		fmt.Printf("Starting capture on interface [%s]\n", iface)
		handle, err = pcap.OpenLive(iface, snaplen, promisc, pcap.BlockForever)
	}

	// check error
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL - Error occurs")
		log.Fatal(err)
	}
	// Set BPF filter
	if err = handle.SetBPFFilter(filter); err != nil {
		fmt.Printf("BPF filter set: [%s]", filter)
		log.Fatal(err)
	}

	// METHOD 1. Use the handle as a packet source to process all packets
	packetBegin := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetBegin.Packets() {
		// Process packet here
		parsePacketFunc(packet) // TODO return something
		fmt.Println(packet)
	}

}

/* PACKET PARSING */
func parsePacketFunc(packet gopacket.Packet) {

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ipv4,
		&ipv6,
		&tcp,
		&udp,
	)
	foundLayerTypes := []gopacket.LayerType{}

	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	if err != nil {
		fmt.Println("Trouble decoding layers: ", err)
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("ALL packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("# ", layer.LayerType())
	}

	// TODO FINISH

	// Ethernet layer parsing
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("[DL layer] --> Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("-- Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("-- Destination MAC: ", ethernetPacket.DstMAC)
		// TODO Check Ethernet Type to decode tunnelings
		fmt.Println("-- Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
		// TODO extract info for stats
	}

	// IP layer parsing
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("[NET Layer] --> IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		/* IP layer variables:
		* Version (4 or 6)
		* IHL (IP Header Length in 32-bit)
		* OS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP or UDP),
		* Checksum, SrcIP, DstIP
		 */
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Printf("-- SRC IP = %s\n", ip.SrcIP)
		fmt.Printf("-- DST IP = %s\n", ip.DstIP)
		fmt.Println("-- TransportProto: ", ip.Protocol)
		fmt.Println()
		// TODO extract info for stats
	}

	// Transport layer parsing
	/// TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("[TRNSP layer] TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		/* TCP layer variables:
		* SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		* Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		 */
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Printf("-- SRC PORT = %s\n", tcp.SrcPort)
		fmt.Printf("-- DST PORT = %s\n", tcp.DstPort)
		fmt.Println("-- FLOW : ", tcp.TransportFlow())
		fmt.Println("-- SYN: ", tcp.SYN)
		fmt.Println("-- Seq Number: ", tcp.Seq)
		fmt.Println()
		// TODO extract info for stats
	}
	/// UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("[TRNSP layer] UDP layer detected.")
		udp, _ := tcpLayer.(*layers.UDP)

		/* UDP layer variables:
		* TODO
		 */
		fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		fmt.Printf("-- SRC PORT = %s\n", udp.SrcPort)
		fmt.Printf("-- DST PORT = %s\n", udp.DstPort)
		fmt.Println("-- FLOW : ", udp.TransportFlow())
		fmt.Println("-- Len = ", udp.Length)
		fmt.Println()
		// TODO extract info for stats
	}

	/* Application layer parsing - PAYLOAD */
	payload := packet.ApplicationLayer()
	if payload != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", payload.Payload())

		/* TODO create dissectors to call here */

		// Search for a string inside the payload
		if strings.Contains(string(payload.Payload()), "ssh") {
			fmt.Println("SSH found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

/*** AUX FUNC ***/

// Help - print command options availlable
func Help(pName string) {
	fmt.Println(pName)
	fmt.Println("\t -h: Print options")
	fmt.Println("\t -l: List the networking devices")
	fmt.Println("\t -i: Specify a network interface")
	fmt.Println("\t -p: Specify a pcap file to read")
}

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
