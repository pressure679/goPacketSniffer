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

// Needs editing from line 179, read comment on line 154 to see what editing

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"encoding/hex"
	"flag"
	"time"
	"os"
)

// Types & functions for adding new
// macs & sorting them by occurence
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

func writepacket(layer layers.Dot11) {
	fo, err0 := os.Create("output.txt")
	if err0 != nil {
		panic(err0)
	}
	defer func() {
		if err1 := fo.Close(); err1 != nil {
			panic(err1)
		}
	}()
	fo.Write(layer.BaseLayer.Contents)
}

// Needs to take inthe right arguement as defined at line 254
func readpacket(desiredmac string, dot11layer layers.LayerTypeDot11) {
	/*
	if ethlayer := packet.Layer(layers.LayerTypeEthernet); ethlayer != nil {
	eth, _ := ethlayer.(*layers.Ethernet)
	//		 if eth.SrcMAC.String() == desiredmac |
	//		 eth.DstMAC.String() == desiredmac {
	fmt.Printf("%s\t\t%s\n", eth.SrcMAC.String(), eth.DstMAC.String())
	}
	if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
	// Get actual TCP data from this layer
	tcp, _ := tcplayer.(*layers.TCP)
	fmt.Printf("TCP: %s\t\t%d\t%s\n", tcp.SrcPort.String(), tcp.DstPort.String())
	} else if udplayer := packet.Layer(layers.LayerTypeUDP); udplayer != nil {
	udp, _ := udplayer.(*layers.UDP)
	fmt.Printf("UDP: %s\t\t%d\t%s\n", udp.SrcPort.String(), udp.DstPort.String())
	}
	if applayer := packet.ApplicationLayer(); applayer != nil {
	// fmt.Println("payload: ", hex.Dump(applayer.Payload()))
	fmt.Println("payload: ", hex.Dump(applayer.Payload()))
	}
	if dot1qlayer := packet.Layer(layers.LayerTypeDot1Q); dot1qlayer != nil {
	dot1q, _ := dot1qlayer.(*layers.Dot1Q)
	fmt.Println("dot1q baselayer\n", dot1q.BaseLayer)
	}
	*/
	dot11, _ := dot11layer.(*layers.Dot11)
	fmt.Println("dot11 address 1\t", dot11.Address1.String())
	fmt.Println("dot11 address 2\t", dot11.Address2.String())
	fmt.Println("dot11 address 3\t", dot11.Address3.String())
	fmt.Println("dot11 address 4\t", dot11.Address4.String())
	fmt.Println("dot11 type\t-\t", dot11.Type)
	fmt.Println("dot11 content\n", hex.Dump(dot11.BaseLayer.Contents))
	fmt.Println("dot11 payload\n", hex.Dump(dot11.BaseLayer.Payload))
	writepacket(dot11)
	/*
	fmt.Println("dot11 content\t", string(dot11.BaseLayer.Contents))
	fmt.Println("dot11 content\t", dot11.BaseLayer.Contents)
	fmt.Println("dot11 payload\t", string(dot11.BaseLayer.Payload))
	fmt.Println("dot11 payload\t", dot11.BaseLayer.Payload)
	*/
}

func main() {

	// Specify which interface to use
	var ifs = flag.String("if", "wlan1", "which interface to use")

	handle0, err0 := pcap.NewInactiveHandle(*ifs);
	if err0 != nil {
		panic(err0)
	}
	err1 := handle0.SetRFMon(true)
	if err1 != nil {
		panic(err1)
	}
	err2 := handle0.SetPromisc(true)
	if err2 != nil {
		panic(err2)
	}
	err3 := handle0.SetSnapLen(1600)
	if err3 != nil {
		panic(err3)
	}
	err4 := handle0.SetTimeout(time.Duration(1) * time.Second)
	if err4 != nil {
		panic(err4)
	}
	/*
	mytssrc := pcap.TimestampSource
	err5 := handle0.SetTimestampSource(mytssrc)
	if err5 != nil {
	panic(err5)
	}
	*/
	handle1, err6 := handle0.Activate()
	if err6 != nil {
		panic(err6)
	}

	// For testing
	// var lc = flag.Bool("local", false, "Capture on privat hardware")
	// flag.Parse()
	// var wlan0 string = "34:23:87:21:1e:8d"

	// This is the mac address to capture from
	var wlan1 string = "00:c0:ca:7e:b8:6a"

	/*
	// sort newmacs.mac by using newmacs.occurence
	// delete least occuring newmacs.mac that
	// are newmacs.related to a high occuring newmacs.mac
	if *lc != true {
	// Start by listing reachable mac units
	var newmacs []macs
	var y byte = 0

	// Capture packets for 15 sec's
	// for mac capture
	now := time.Now()
	later := time.Now().Add(time.Duration(15) * time.Second)
	nowtwo := time.Now()
	var changetime bool = true
	var listmacs bool = true
	packetSource := gopacket.NewPacketSource(handle1, handle1.LinkType())
	for packet := range packetSource.Packets() {
	for listmacs {
	if now.Second() >= 45 {
	if nowtwo.Minute() != later.Minute() {
	changetime = false
	}
	if changetime == true {
	addthis := time.Duration(1)
	later.Add(addthis * time.Minute)
	subthis := time.Duration(75)
	later.Sub(subthis * time.Second)
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
	for i := y; i < 99; i++ {
	mymacs[y].mac = mymacs[y - 1].mac
	mymacs[y].related = mymacs[y - 1].related
	mymacs[y].occurence = mymacs[y - 1].occurence
	}
	}
	// Print mac units by occurence
	fmt.Println(x, " ", mymacs[x].mac)
	}
	}

	// Choose which mac(s) to capture packets from
	var nummacstocap uint8
	var chosenmacs []uint8
	fmt.Printf("Select number of macs to capture: ")
	fmt.Scanf("%d", nummacstocap)
	for x := 0; x <= int(nummacstocap); x++ {
	fmt.Printf("Choose which mac(s) to capture from ")
	fmt.Scanf("%d", chosenmacs[x])
	}
	for x := 0; x <= len(chosenmacs); x++ {
	
	}
	}
	*/
	// Start a packet capture on port 80.
	// Capture 5000 packets & decrypt dump.
	// Found password/key is stored in txt file.
	if err0 != nil {
		panic(err0)
	}
	packetSource := gopacket.NewPacketSource(handle1, handle1.LinkType())
	for packet := range packetSource.Packets() {
		if dot11layer := packet.Layer(layers.LayerTypeDot11); dot11layer != nil {
			/*
			if *lc == true {
			for x := 0; x < len(mymacs); x++ {
			readpacket(mymacs[x].mac, packet)
			}
			} else {
			*/
			// readpacket(wlan0, packet)
			readpacket(wlan1, dot11layer)
		}
	}
}
