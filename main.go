/*
* GiantStepNet - a jazzy protocol parser in GO
* @author - Michele Campus (michelecampus5@gmail.com)
* NOTE: WORK IN PROGRESS
 */

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	programName := "GiantStepNet"
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

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// TODO Process packet here
		fmt.Println(packet)
	}
}

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
		if device.Description != "" {
			fmt.Println("Description: ", device.Description)
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
