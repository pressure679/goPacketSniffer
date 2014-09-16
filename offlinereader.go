// Copyright (C) 2014 Vittus Peter Ove Maqe Mikiassen
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"flag"
	"encoding/hex"
)

func main() {
  fileflag := flag.String("file", "", "The file to read data from")
	flag.Parse()
	file := []byte(*fileflag)
	handle, err := pcap.OpenOffline(string(file))
	if err != nil {
		panic(err)
	}
	pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range pktsrc.Packets() {
		if eapollayer := pkt.Layer(layers.LayerTypeEAPOL); eapollayer != nil {
			fmt.Printf("\nEAPOL Packet\n\n")
		}
		if dot11layer := pkt.Layer(layers.LayerTypeDot11); dot11layer != nil {
			dot11, _ := dot11layer.(*layers.Dot11)
			fmt.Println("dot11 proto:\n", dot11.Proto)
			fmt.Printf("dot11  payload:\n%s\n", dot11.Payload)
			fmt.Printf("dot11  contents:\n%s\n", dot11.Contents)
			fmt.Printf("dump:\n%s\n", pkt.Dump())
		}
		if dot11datalayer := pkt.Layer(layers.LayerTypeDot11Data); dot11datalayer != nil {
			dot11data, _ := dot11datalayer.(*layers.Dot11Data)
			payload := dot11data.BaseLayer.Payload
			contents := dot11data.BaseLayer.Contents
			fmt.Println("dot11data payload:\n", payload)
			fmt.Println("dot11data content:\n", contents)
			fmt.Printf("dump:\n%s\n", pkt.Dump())
		}
		if iplayer := pkt.Layer(layers.LayerTypeIPv4); iplayer != nil {
			ip, _ := iplayer.(*layers.IPv4)
			fmt.Printf("%s\t\t%d\t%s\n", ip.SrcIP.String(), ip.TTL, ip.DstIP.String())
			fmt.Printf("dump:\n%s\n", pkt.Dump())
		}
		if tcplayer := pkt.Layer(layers.LayerTypeTCP); tcplayer != nil {
			tcp, _ := tcplayer.(*layers.TCP)
			fmt.Printf("TCP: %d\t\t%d\t%d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Printf("dump:\n%s\n", pkt.Dump())
		} else if udplayer := pkt.Layer(layers.LayerTypeUDP); udplayer != nil {
			udp, _ := udplayer.(*layers.UDP)
			fmt.Printf("UDP: %d\t\t%d\t%d\n", udp.SrcPort, udp.DstPort)
		}
		if applayer := pkt.ApplicationLayer(); applayer != nil {
			fmt.Println("payload:")
			fmt.Printf(hex.Dump(applayer.Payload()))
		}
	}
}
