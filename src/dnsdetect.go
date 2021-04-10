// Minqi Shi
// 111548035
// References:
// And there are other references in the code
// 	https://pkg.go.dev/github.com/google/gopacket/
// 	https://pkg.go.dev/github.com/google/gopacket/pcap
// 	https://golang.org/doc/
//  https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ipPortMap struct {
	// idPacketInfoMap map[string]packetInfo
	// requestMap      map[string]int // map[TXID]counter
	ports map[string]portPacketMap // map[Port Number]portPacketMap
}

type portPacketMap struct {
	idPacketInfoMap map[string]packetInfo
	requestMap      map[string]int // map[TXID]counter
}

type packetInfo struct {
	Answers []layers.DNSResourceRecord
	Time    time.Time
	Counter int
}

var (
	ethLayer      layers.Ethernet
	ipv4Layer     layers.IPv4
	udpLayer      layers.UDP
	dnsLayer      layers.DNS
	decodedLayers []gopacket.LayerType          = make([]gopacket.LayerType, 0, 4)
	decoder       *gopacket.DecodingLayerParser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)
	answer        layers.DNSResourceRecord
	// ipMap         map[string]ipaddr = make(map[string]ipaddr)
	ipMap   map[string]ipPortMap = make(map[string]ipPortMap)
	tempID  string
	srcIP   string
	dstIP   string
	srcPort string
	dstPort string
)

// Returns a string of Answers
func sprintIPFromAnswers(Answers []layers.DNSResourceRecord) (s string) {
	isFirst := true
	for i := 0; i < len(Answers); i++ {
		if Answers[i].Type != layers.DNSTypeA {
			continue
		}
		if !isFirst {
			s += "         " + Answers[i].String() + "\n"
		} else {
			s = Answers[i].String() + "\n"
			isFirst = false
		}
	}
	return s
}

// Add the new packetInfo to the map
func newPacketInfo(victimIP string, victimPort string, txid string, dnsLayer *layers.DNS, time time.Time, counter int) {
	var tempAnswer []layers.DNSResourceRecord
	if len(dnsLayer.Answers) == 0 {
		return
	}
	for i := 0; i < len(dnsLayer.Answers); i++ {
		tempAnswer = append(tempAnswer, dnsLayer.Answers[i])
	}
	pi := packetInfo{
		Answers: tempAnswer,
		Time:    time,
		Counter: counter + 1,
	}
	// idPacketInfoMap[tempID] = pi
	ipMap[victimIP].ports[victimPort].idPacketInfoMap[txid] = pi
}

func detectDNSSpoof(packetData []byte, t time.Time) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Some unexpected error happened: %v \nBut the detector would continue to work :)...\n", r)
		}
	}()
	if err := decoder.DecodeLayers(packetData, &decodedLayers); err != nil {
		fmt.Print("There is a decoding error: ")
		fmt.Println(err)
		return
	}
	if len(decodedLayers) != 4 {
		fmt.Println("The number of layers is not 4!")
		return
	}
	tempID = fmt.Sprintf("%x", dnsLayer.ID)
	srcIP = fmt.Sprint(ipv4Layer.SrcIP)
	dstIP = fmt.Sprint(ipv4Layer.DstIP)
	srcPort = fmt.Sprint(udpLayer.SrcPort)
	dstPort = fmt.Sprint(udpLayer.DstPort)

	// If a query, the srcIP is the IP of the victim
	if !dnsLayer.QR {

		// if an new victim ip
		if _, found := ipMap[srcIP]; !found {
			ipMap[srcIP] = ipPortMap{
				ports: make(map[string]portPacketMap),
			}
		}

		// if an new victim port
		if _, found := ipMap[srcIP].ports[srcPort]; !found {
			ipMap[srcIP].ports[srcPort] = portPacketMap{
				idPacketInfoMap: make(map[string]packetInfo),
				requestMap:      make(map[string]int),
			}
		}

		// fmt.Println(tempID)
		// if there is an request, record the TXID and increment the counter
		if _, found := ipMap[srcIP].ports[srcPort].requestMap[tempID]; found {
			ipMap[srcIP].ports[srcPort].requestMap[tempID] = ipMap[srcIP].ports[srcPort].requestMap[tempID] + 1
		} else {
			ipMap[srcIP].ports[srcPort].requestMap[tempID] = 1
		}
		return
	} else { // If not a query, the dstIP is the IP of the victim
		if _, found := ipMap[dstIP]; !found {
			// 	ipMap[dstIP] = ipaddr{
			// 		idPacketInfoMap: make(map[string]packetInfo),
			// 		requestMap:      make(map[string]int),
			// 	}
			// }
			ipMap[dstIP] = ipPortMap{
				ports: make(map[string]portPacketMap),
			}
		}
		// if an new victim port
		if _, found := ipMap[dstIP].ports[dstPort]; !found {
			ipMap[dstIP].ports[dstPort] = portPacketMap{
				idPacketInfoMap: make(map[string]packetInfo),
				requestMap:      make(map[string]int),
			}
		}
	}
	// If not a query, the dstIP is the IP of the victim
	// if a new txid, add the newPacketInfo
	if _, found := ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID]; !found {
		newPacketInfo(dstIP, dstPort, tempID, &dnsLayer, t, 0)
		return
	}

	// Example output
	// 20210309-15:08:49.205618  DNS poisoning attempt
	// TXID 0x5cce Request www.example.com
	// Answer1 [List of IP addresses]
	// Answer2 [List of IP addresses]
	if _, found := ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID]; found {
		c := ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID].Counter
		// if same ip, same port, same txid, large time interval, then it's fine
		// if t.Sub(ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID].Time) > 800*time.Millisecond {
		// 	newPacketInfo(dstIP, dstPort, tempID, &dnsLayer, t, c)
		// 	return
		// }
		// // if for different hostname, it's fine
		// if bytes.Compare(ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID].Answers[0].Name, dnsLayer.Answers[0].Name) != 0 {
		// 	newPacketInfo(dstIP, dstPort, tempID, &dnsLayer, t, c)
		// 	return
		// }
		// If there are more request than answer with the same TXID, it is not an attack
		if ipMap[dstIP].ports[dstPort].requestMap[tempID] >= ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID].Counter+1 {
			newPacketInfo(dstIP, dstPort, tempID, &dnsLayer, t, c)
			return
		}

		fmt.Printf("%v", t.Format("2006-01-02 15:04:05.000000 "))
		fmt.Print(" DNS poisoning attempt\n")
		fmt.Printf("TXID 0x%v Request %v\n", tempID, string(dnsLayer.Answers[0].Name))
		fmt.Print("Answer1: ", sprintIPFromAnswers(ipMap[dstIP].ports[dstPort].idPacketInfoMap[tempID].Answers))
		fmt.Print("Answer2: ", sprintIPFromAnswers(dnsLayer.Answers))
		fmt.Println("-------------------------")

	}
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
		if strings.Index(expr_string, "udp") == -1 {
			expr_string += " and udp"
		}
		if strings.Index(expr_string, "port 53") == -1 {
			expr_string += " and port 53"
		}
		// fmt.Printf("Expr String: %v\n", expr_string)
	} else {
		// expr_string = "udp dst port 53"
		expr_string = "udp and port 53"
		// expr_string = ""
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
			fmt.Println("Reading " + filepath + " on " + inter_face + " [" + expr_string + "]")
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				packetData := packet.Data()
				time := packet.Metadata().Timestamp
				detectDNSSpoof(packetData, time)
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
			fmt.Println("Listening on " + inter_face + " [" + expr_string + "]")
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				packetData := packet.Data()
				time := packet.Metadata().Timestamp
				detectDNSSpoof(packetData, time)
			}
		}
	}

}
