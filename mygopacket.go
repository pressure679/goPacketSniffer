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

	// For testing
	var lc = flag.Bool("local", false, "Cap on local")
	flag.Parse()

	// sort newmacs.mac by using newmacs.occurence
	// delete least occuring newmacs.mac that
	// are newmacs.related to a high occuring newmacs.mac
	if *lc != true {
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

		// Needs some minor changes, I'll get to it
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
	
	// Needs major editing from here!
	// Needs to capture only from mymacs narrowed down by last loops, and only from port 80.
	// Needs to save payload and know which MAC the payload belongs to.
	// Save the data to RAM or HDD and decrypt/encrypt data for password recovery.
	// The password recovery can be with or without ARP Poisoning, but should be if
	// you intend to let the AP decrypt the data for you.
	
	// The encrypt/decrypt AI is going to be tricky. I have a file of
	// 500 most common passwords & files with months, years & dates + 
	// 50 most used baby names, these should work as a 1st option cracking,
	// along with some dumbass passwords like "god" or "sexy".
	// You know, just have fun implementing an AI cracker, and notify me if you have an idea.
	
	// Encryption is for encrypting html tags with different passwords & IV's,
	// and see if the encryption matches a string in the payload from packets
	
	// You should either decrypt or encrypt, up to you,
	// I'm going to test both and see which one is faster.
	
	// I don't excatly know yet how wpa2 encryption works, but hopefully wpa2crypt.go will
	// work, of course with a loop to go through different passwords & IV's.
	
	// Start a packet capture on port 80.
	// Capture 5000 packets & decrypt dump.
	// Found password/key is stored in txt file.
	if err0 != nil {
		panic(err0)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() { 
		if ethlayer := packet.Layer(layers.LayerTypeEthernet); ethlayer != nil {
			eth, _ := ethlayer.(*layers.Ethernet)
			for x := 0; x <= int(nummacstocap); x++ {
				if eth.SrcMAC.String() == || eth.DstMAC.String()
				fmt.Printf("%d\t\t%d\n", eth.SrcMAC.String(), eth.DstMAC.String())
			}
			if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
				// Get actual TCP data from this layer
				tcp, _ := tcplayer.(*layers.TCP)
				fmt.Printf("TCP: %d\t\t%d\t%d\n", tcp.SrcPort, tcp.DstPort)
			} else if udplayer := packet.Layer(layers.LayerTypeUDP); udplayer != nil {
				udp, _ := udplayer.(*layers.UDP)
				fmt.Printf("UDP: %d\t\t%d\t%d\n", udp.SrcPort, udp.DstPort)
				if applayer := packet.ApplicationLayer(); applayer != nil {
					// fmt.Println("payload: ", hex.Dump(applayer.Payload()))
					fmt.Println("payload: ", hex.Dump(applayer.Payload()))
				}
			}
		}
	}
}
