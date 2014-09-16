//    This software is for intended for WPA-2 cracking, with or without ARP Poisoning. - Not yet finished
//    Copyright (C) 2014  Vittus Peter Ove Maqe Mikiassen
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"flag"
	"encoding/hex"
	"time"
)
func main() {
	// edit

	/*
	addr := flag.String("addr", "", "which address to capture from")
	mac := flag.String("mac", "", "which mac address to capture from")
	file	:= flag.String("file", "", "file name to write")
	*/

	ifs := flag.String("if", "", "which interface to use")
	// RFMon := flag.Bool("rfmon", false, "capture in rfmon mode")
	CheckDot11 := flag.Bool("dot11", false, "capture 802.11 packets")
	CheckEAPOL := flag.Bool("eapol", false, "capture eapol packets")
	GetTCPIPSuite := flag.Bool("tcpipsuite", false, "show what's in each layer in the TCP/IP-Suite")
	flag.Parse()

	handle0, err0 := pcap.NewInactiveHandle(*ifs);
	if err0 != nil { panic(err0) }
	/*
	err1 := handle0.SetRFMon(*RFMon)
	if err1 != nil { panic(err1) }
	 */
	err2 := handle0.SetPromisc(true)
	if err2 != nil { panic(err2) }
	err3 := handle0.SetSnapLen(1600)
	if err3 != nil { panic(err3) }
	err4 := handle0.SetTimeout(time.Duration(1) * time.Second)
	if err4 != nil { panic(err4) }
	handle, err6 := handle0.Activate()
	if err6 != nil { panic(err6) }
	EAPOLCount := -1
	var amac, smac, anonce, snonce []byte
	PktSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range PktSrc.Packets() {
		if *GetTCPIPSuite == true {
			fmt.Println("TCP/IP-Suite:")
			GetTCPIPLayer(pkt)
		}
		if *CheckEAPOL == true {
			EAPOLCount++
			amac, smac, anonce, snonce = GetEAPOL(EAPOLCount, pkt)
			fmt.Printf("AMAC:\t%s\nSMAC:\t%s\nANONCE:\t%s\nSNONCE:\t%s\n", amac, smac, anonce, snonce)
		}
		if *CheckDot11 == true {
			GetDot11(pkt)
		}
		if dot11datalayer := pkt.Layer(layers.LayerTypeDot11Data); dot11datalayer != nil {
			dot11data, _ := dot11datalayer.(*layers.Dot11Data)
			payload := dot11data.BaseLayer.Payload
			contents := dot11data.BaseLayer.Contents
			fmt.Println("dot11data payload:\n", payload)
			fmt.Println("dot11data content:\n", contents)
		}
		if iplayer := pkt.Layer(layers.LayerTypeIPv4); iplayer != nil {
			ip, _ := iplayer.(*layers.IPv4)
			fmt.Printf("%s\t\t%d\t%s\n", ip.SrcIP.String(), ip.TTL, ip.DstIP.String())
		}
		if tcplayer := pkt.Layer(layers.LayerTypeTCP); tcplayer != nil {
			tcp, _ := tcplayer.(*layers.TCP)
			fmt.Printf("TCP: %d\t\t%d\t%d\n", tcp.SrcPort, tcp.DstPort)
		} else if udplayer := pkt.Layer(layers.LayerTypeUDP); udplayer != nil {
			udp, _ := udplayer.(*layers.UDP)
			fmt.Printf("UDP: %d\t\t%d\t%d\n", udp.SrcPort, udp.DstPort)
		}
	}
}
func GetEAPOL(EAPCount int, pkt gopacket.Packet) ([]byte, []byte, []byte, []byte) {
	var amac, smac, anonce, snonce []byte
	if EAPOLLayer := pkt.Layer(layers.LayerTypeEAPOL); EAPOLLayer != nil {
		if EAPCount == 0 {
			amac = pkt.Data()[40:46]
			smac = pkt.Data()[28:34]
			anonce = pkt.Data()[73:105]
		} else if EAPCount == 1 {
			snonce = pkt.Data()[73:105]
		}
	}
	return amac, smac, anonce, snonce
}
func GetDot11(pkt gopacket.Packet) {
	if Dot11Layer := pkt.Layer(layers.LayerTypeDot11); Dot11Layer != nil {
		Dot11, err := Dot11Layer.(*layers.Dot11)
		if err != false { panic(err) }
		fmt.Println("Dot11 proto:\n", Dot11.Proto)
		fmt.Printf("Dot11	 payload:\n%s\n", Dot11.Payload)
		fmt.Printf("Dot11	 contents:\n%s\n", Dot11.Contents)
	}
}
func GetSSID(pkt gopacket.Packet) (string, bool) {
	data := pkt.Data()
	var dst []byte
	ssidlen, err := hex.Decode(dst, data)
	if err != nil {
		return "", true
	}
	ssid := string(data[26:26 + ssidlen])
	return ssid, false
}
/*
func Dump(data []byte, strfile string) error {
	file, err := os.Create(strfile)
	if err != nil { return err }
	writer := pcapgo.NewWriter(file)
	writer.WritePacket(gopacket.CaptureInfo{...}, data)
	defer return err
	file.Close()
}
*/
func GetTCPIPLayer(pkt gopacket.Packet) {
	if LLayer := pkt.LinkLayer(); LLayer != nil {
		fmt.Println("\tLink Layer:\n", hex.Dump(pkt.LinkLayer().LayerPayload()))
		/*
		LL, err := LLayer.(*layers.LinkLayer)
		if err != nil { panic(err) }
		fmt.Println("Link Layer:")
		fmt.Printf(hex.Dump(LL.Payload()))
		 */
	}
	if NwLayer := pkt.NetworkLayer(); NwLayer != nil {
		fmt.Println("\tNetwork Layer:\n", hex.Dump(pkt.NetworkLayer().LayerPayload()))
		/*
		Nw, err := NwLayer.(*layers.NetworkLayer)
		if err != nil { panic(err) }
		fmt.Println("Network Layer payload:")
		fmt.Printf(hex.Dump(Nw.Payload()))
		 */
	}
	if TsLayer := pkt.TransportLayer(); TsLayer != nil {
		fmt.Println("\tTransport Layer\n", hex.Dump(pkt.TransportLayer().LayerPayload()))
		/*
		Ts, err := TsLayer.(*layers.TransportLayer)
		if err != nil { panic(err) }
		fmt.Println("Transport Layer payload:")
		fmt.Printf(hex.Dump(Ts.Payload()))
		 */
	}
	if AppLayer := pkt.ApplicationLayer(); AppLayer != nil {
		fmt.Println("\tApplication Layer:\n", hex.Dump(pkt.ApplicationLayer().LayerPayload()))
		/*
		App, err := AppLayer.(*layers.ApplicationLayer)
		if err != nil { panic(err) }
		fmt.Println("AppLayer payload:\n")
		fmt.Printf(hex.Dump(App.Payload()))
		 */
	}
}
