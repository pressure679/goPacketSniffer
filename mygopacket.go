package main
import (
	"fmt"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"encoding/hex"
	"flag"
)
type macs struct {
	occurence byte
	mac string
	related string
}
type mysort []byte
func (a mysort) Len() int {
	return len(a)
}
func (a mysort) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a mysort) Less(i, j int) bool {
	return a[i] < a[j]
}
func main() {
	/*
	var ifs = flag.String("if", "eth0", "which interface to use")
	var promiscbool = flag.Bool("promisc", false, "whether to capture in promiscuous mode or not")
	var ipbool = flag.Bool("ip", false, "whether to show ip address of packets or not")
	var ethernetbool = flag.Bool("ethernet", false, "whether to show MAC or not")
	var portbool = flag.Bool("port", false, "whether to show port or not")
	var payloadbool = flag.Bool("payload", false, "whether to show payload or not")
	var icmpv4bool = flag.Bool("icmp", false, "whether to show packets are icmp or not")
	var arpbool = flag.Bool("arp", false, "whether to show packets are arp or not")
	var pppbool = flag.Bool("ppp", false, "whether to show packets are ppp or not")
	var pppoebool = flag.Bool("pppoe", false, "whether to show packets are pppoe or not")
	var rudpbool = flag.Bool("rudp", false, "whether to show packets are rudp or not")
	var sctpbool = flag.Bool("sctp", false, "whether to show packets are sctp or not")
	var snapbool = flag.Bool("snap", false, "whether to show packets are snap or not")
	 */
	flag.Parse()

	// Start by listing reachable mac units
	var newmacs []macs
	var y byte = 0
	handle, err0 := pcap.OpenLive("wlan0", 65535, true,	0)
	if err0 != nil {
		panic(err0)
	}
	now := time.Now()
	later := time.Now().Add(Time.Duration(15)*time.Second)
	nowtwo := time.Now()
	var changetime bool = true
	var listmacs bool = true
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for listmacs {
			if now.Second() >= 45 {
				if nowtwo.Minute() != later.Minute() {
					changetime = false
				}
				if changetime == true {
					later.Add(time.Duration(1)*time.Minute)
					later.Sub(time.Duration(75)*time.Second)
				}
			}
			now = time.Now()
			if now <= later {
				listmacs = false
			}
			if ethlayer := packet.Layer(layers.LayerTypeEthernet); ethlayer != nil {
				eth, _ := ethlayer.(*layers.Ethernet)
				if macsstr[99] == "" {
					for x := 0; x < 100; x++ {
						if newmacs[x].mac == "" {
							continue
						}
						if eth.SrcMAC.String() == newmacs.mac[x] {
							newmacs.occurence[x]++
							break
						}	else {
							if newmacs[x].mac == "" {
								newmacs[x].mac = eth.SrcMAC.String()
								newmacs[x].related = eth.DstMAC.String()
								fmt.Println(y, " ", newmacs.mac[y])
								y++
								break
							}
						}
						if eth.DstMAC.String() == newmacs.mac[x] {
							break
							newmacs.occurence[x]++
						} else {
							if newmacs.mac[x] == "" {
								newmacs.mac[x] = eth.DstMAC.String()
								newmacs.related[x] = eth.SrcMAC.String()
								fmt.Println(y, " ", newmacs.mac[y])
								y++
								break
							}
						}
					}
				}	
			}
		}
	}

	// sort newmacs.mac by using newmacs.occurence
	// delete least occuring newmacs.mac that
	// are newmacs.related to a high occuring newmacs.mac
	var nummacs uint8
	sort.Sort(mysort(mymacs))
	for x := 99; x >= 0; x-- {
		if mymacs[x].mac == "" {
			continue
		} else {
			nummacs = uint8(x)
		}
		for y := 0; y < 100; y++ {
			if mymacs[x].mac == mymacs[y].related {
				for i := y; i < 
				mymacs[y].mac = ""
				mymacs[y].related = ""
				mymacs[y].occurence = -1
			}
		}
		// Print mac units by occurence
		fmt.Println(x, " ", mymacs[x].mac)
	}

	// Choose which mac(s) to capture packets from
	var nummacstocap uint8
	var chosenmacs []uint8
	fmt.Printf("Select number of macs to capture: ")
	fmt.Scanf("%d", nummacstocap)
	for x := 0; x <= int(nummacstocap); x++ {
		fmt.Printf("Choose which mac to capture from ")
		fmt.Scanf("%d", chosenmacs[x])
	}

	// Start a packet capture on port 80.
	// Capture 5000 packets & decrypt dump.
	// Found password/key is stored in txt file.
	if err0 != nil {
		panic(err0)
	}

	v
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() { 
			if *ipbool == true {
				if iplayer := packet.Layer(layers.LayerTypeIPv4); iplayer != nil {
					ip4, _ := iplayer.(*layers.IPv4)
				fmt.Printf("%d\t%d\t\t%d\n", ip4.SrcIP.String(), ip4.TTL, ip4.DstIP.String())
				}
				if *portbool == true {
					if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
						// Get actual TCP data from this layer
						tcp, _ := tcplayer.(*layers.TCP)
						fmt.Printf("TCP: %d\t\t%d\t%d\n", tcp.SrcPort, tcp.DstPort)
					} else if udplayer := packet.Layer(layers.LayerTypeUDP); udplayer != nil {
						udp, _ := udplayer.(*layers.UDP)
						fmt.Printf("UDP: %d\t\t%d\t%d\n", udp.SrcPort, udp.DstPort)
					}
				}
				if *ethernetbool == true {
					if ethlayer := packet.Layer(layers.LayerTypeEthernet); ethlayer != nil {
						eth, _ := ethlayer.(*layers.Ethernet)
						fmt.Printf("%d\t\t%d\n", eth.SrcMA,.String(), eth.DstMAC.String())
					}
				}
				if *arpbool == true {
					if arplayer := packet.Layer(layers.LayerTypeARP); arplayer != nil {
						fmt.Println("This is in ARP packet!")
						arp, _ := arplayer.(*layers.ARP)
						fmt.Printf("From src MAC %d port %d\nto dst MAC %d port %d", arp.SourceHwAddress, arp.SourceProtAddress, arp.DstHwAddress, arp.DstProtAddress)
						fmt.Println("-\t-\t-\t-\t-")
					}
				}
				if *payloadbool == true {
					if applayer := packet.ApplicationLayer(); applayer != nil {
						// fmt.Println("payload: ", hex.Dump(applayer.Payload()))
						fmt.Println("payload: ", hex.Dump(applayer.Payload()))
					}
				}
				if *icmpv4bool == true {
					if icmpv4layer := packet.Layer(layers.LayerTypeICMPv4); icmpv4layer != nil {
						icmp, _ := icmpv4layer.(*layers.ICMPv4)
						fmt.Println(icmp)
					}
				}
				if *pppbool == true {
					if ppplayer := packet.Layer(layers.LayerTypePPP); ppplayer != nil {
						ppp, _ := ppplayer.(*layers.PPP)
						fmt.Println(ppp)
					}
				}
				if *pppoebool == true {
					if pppoelayer := packet.Layer(layers.LayerTypePPPoE); pppoelayer != nil {
						pppoe, _ := pppoelayer.(*layers.PPPoE)
						fmt.Println(pppoe)
					}
				}
				if *rudpbool == true {
					if rudplayer := packet.Layer(layers.LayerTypeRUDP); rudplayer != nil {
						rudp, _ := rudplayer.(*layers.RUDP)
						fmt.Println(rudp)
					}
				}
				if *sctpbool == true {
					if sctplayer := packet.Layer(layers.LayerTypeSCTP); sctplayer != nil {
						sctp, _ := sctplayer.(*layers.SCTP)
						fmt.Println(sctp)
					}
				}
				if *snapbool == true {
					if snaplayer := packet.Layer(layers.LayerTypeSNAP); snaplayer != nil {
						snap, _ := snaplayer.(*layers.SNAP)
						fmt.Println(snap)
					}
				}
				fmt.Printf("\n")
			}
		}
	}
}
