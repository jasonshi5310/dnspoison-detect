// Minqi Shi
// 111548035
// References:
// And there are other references in the code
// 	https://pkg.go.dev/github.com/google/gopacket/
// 	https://pkg.go.dev/github.com/google/gopacket/pcap
// 	https://golang.org/doc/
//  https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Example output
// 20210309-15:08:49.205618  DNS poisoning attempt
// TXID 0x5cce Request www.example.com
// Answer1 [List of IP addresses]
// Answer2 [List of IP addresses]

func detectDNSSpoof(packet gopacket.packet) {

}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("", r)
		}
	}()
	// fmt.Println("Hello world!")
	argv := os.Args[1:]      // Argument vector
	argv_length := len(argv) // Length of the arguments

	// fmt.Printf("Argument vector: %v\n", argv)
	// fmt.Printf("Vector Length: %v\n", argv_length)

	var (
		inter_face  string = "-1"
		filepath    string = "-1"
		expr        []string
		expr_string string
		optind      int = 0
	)

	for i := 0; i < argv_length; i = i + 2 {
		var opt string = argv[i]
		if opt[0] != '-' {
			continue
		}
		optind += 2
		switch opt {
		case "-i":
			if inter_face != "-1" {
				fmt.Println("Multiple interfaces provided!")
				return
			}
			if i+1 == argv_length {
				fmt.Println("Missing arguments!")
				return
			}
			inter_face = argv[i+1]
			// fmt.Println("Interface:", inter_face)
		case "-r":
			if filepath != "-1" {
				fmt.Println("Multiple files provided!")
				return
			}
			if i+1 == argv_length {
				fmt.Println("Missing arguments!")
				return
			}
			filepath = argv[i+1]
			// fmt.Println("File:", filepath)
		default:
			fmt.Println("Unrecognized command!")
			return
		}
	}
	if optind < argv_length {
		expr = argv[optind:]
		// fmt.Printf("Expr: %v\n", expr)
	}
	if len(expr) != 0 {
		for i := 0; i < len(expr); i++ {
			expr_string += expr[i]
			if i != len(expr)-1 {
				expr_string += " "
			}
		}
		// fmt.Printf("Expr String: %v\n", expr_string)
	} else {
		expr_string = ""
	}
	//https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	if inter_face == "-1" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			panic(err)
		}
		inter_face = devices[0].Name
	}

	//https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
	if filepath != "-1" {
		if handle, err := pcap.OpenOffline(filepath); err != nil {
			panic(err)
		} else if err := handle.SetBPFFilter(expr_string); err != nil { // BPF
			panic(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				detectDNSSpoof(packet)
			}
		}
		// live cap
	} else {
		if handle, err := pcap.OpenLive(inter_face, 1600, true, pcap.BlockForever); err != nil {
			panic(err)
		} else if err := handle.SetBPFFilter(expr_string); err != nil { // BPF
			panic(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				detectDNSSpoof(packet)
			}
		}
	}

}