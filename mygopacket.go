package main
import (
	"fmt"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
)

func main() {
	if handle, err0 := pcap.OpenLive("eth0", 1600, true, 0); err0 != nil {
		panic(err0)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if iplayer := packet.Layer(layers.LayerTypeIPv4); iplayer != nil {
				fmt.Println("This is an IP packet!")
				ip4, _ := iplayer.(*layers.IPv4)
				fmt.Printf("From src ip %d to dst ip %d", ip4.SrcIP, ip4.DstIP)
				if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
					fmt.Println("This is a TCP packet!")
					// Get actual TCP data from this layer
					tcp, _ := tcplayer.(*layers.TCP)
					fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
				} else if udplayer := packet.Layer(layers.LayerTypeUDP); udplayer != nil {
					fmt.Println("This is an UDP packet!")
					udp, _ := udplayer.(*layers.UDP)
					fmt.Printf("From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
			}
			if ethlayer := packet.Layer(layers.LayerTypeEthernet); ethlayer != nil {
					fmt.Println("This is an Ethernet packet!")
					eth, _ := ethlayer.(*layers.Ethernet)
					fmt.Printf("From src MAC %d to dst MAC %d\n", eth.SrcMAC, eth.DstMAC)
				}
			}
		}
	}
}