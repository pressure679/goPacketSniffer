//    This software is for intended for WPA-2 cracking, with brute force - Need IP-checker and PTK-generator
//    Copyright (C) 2023  Vittus Peter Ove Maqe Mikiassen
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
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"flag"
	"encoding/hex"
	"time"
)
func main() {
	// edit
	var SrcIP, DstIP []byte

	ifs := flag.String("if", "", "which interface to use")
	// RFMon := flag.Bool("rfmon", false, "capture in rfmon mode")
	CheckDot11 := flag.Bool("dot11", false, "capture 802.11 packets")
	CheckEAPOL := flag.Bool("eapol", false, "capture eapol packets")
	GetTCPIPSuite := flag.Bool("tcpipsuite", false, "show what's in each layer in the TCP/IP-Suite")
	flag.Parse()

  password := []byte("Induction") // 32 bytes
  salt := []byte("Coherer")
	key := make([]byte, 16)
	copy(key[:], keystr)

	key := HashPassword(password, salt)

	// add an option to choose to read from file or interface
	handle0, err0 := pcap.NewInactiveHandle(*ifs);
	if err0 != nil { panic(err0) }
	err1 := handle0.SetRFMon(*RFMon)
	if err1 != nil { panic(err1) }
	err2 := handle0.SetPromisc(true)
	if err2 != nil { panic(err2) }
	err3 := handle0.SetSnapLen(1600)
	if err3 != nil { panic(err3) }
	err4 := handle0.SetTimeout(time.Duration(1) * time.Second)
	if err4 != nil { panic(err4) }
	handle, err6 := handle0.Activate()
	if err6 != nil { panic(err6) }
	EAPOLCount := -1
	PktSrc := gopacket.NewPacketSource(handle, handle.LinkType())

	var amac, smac, anonce, snonce []byte
	var data, alldata []byte
	var decrerr bool
	for pkt := range PktSrc.Packets() {
		if *GetTCPIPSuite == true {
			fmt.Println("TCP/IP-Suite:")
			GetTCPIPLayer(pkt)
		}
		if *CheckEAPOL == true {
			EAPOLCount++
			amac, smac, anonce, snonce = GetEAPOL(EAPOLCount, pkt)
			fmt.Printf("AMAC:\t%s\nSMAC:\t%s\nANONCE:\t%s\nSNONCE:\t%s\n", amac, smac, anonce, snonce)
			if iplayer := pkt.Layer(layers.LayerTypeIPv4); iplayer != nil {
				ip, _ := iplayer.(*layers.IPv4)
				fmt.Printf("%s\t\t%d\t%s\n", ip.SrcIP.String(), ip.TTL, ip.DstIP.String())
				dataenc := ConfirmData(pkt, SrcIP, DstIP)
				if dataenc == true {
					data, decrerr = Decrypt(key, pkt.Data())
					alldata = alldata + data
					if decrerr != nil {
						fmt.Println("error decrypting data")
						return
					}
				}
			}
		}
		if tcplayer := pkt.Layer(layers.LayerTypeTCP); tcplayer != nil {
			tcp, _ := tcplayer.(*layers.TCP)
			fmt.Printf("TCP: %d\t\t%d\t%d\n", tcp.SrcPort, tcp.DstPort)
		}
	}
	fmt.Println(alldata)
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
func Dump(data []byte, strfile string) error {
	file, err := os.Create(strfile)
	if err != nil { return err }
	writer := pcapgo.NewWriter(file)
	writer.WritePacket(gopacket.CaptureInfo{...}, data)
	defer return err
	file.Close()
}
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
func HashPassword(password, salt []byte, keylen int) []byte {
	return pbkdf2.Key(password, salt, 4096, keylen, sha1.New)
}
func PTKGen(anonce, snonce, amac, smac, pmk string) []byte {
	b := amac + smac + snonce + anonce
	var ptk []byte
	var buff bytes.Buffer
	for i := 0; i < 5; i++ {
		passwordstr := "Pairwise key expansion" + "\x00" + b + string(i)
		password := []byte(passwordstr)
		salt := []byte(pmk)
		ptk = HashPassword(salt, password, 20)
		buff.Write(ptk)
	}
	ptk = buff.Bytes()
	return ptk
}
// pkcs#7 unpadding
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}
	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in) - int(padding)]
}
// for clearing pmk, ssid & password you've provided,
// but not used atm.
func Clear(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0;
	}
}
// aes-cbc decrypter with pkcs#7 unpadding
func Decrypt(k, in []byte) []byte, bool {
	if len(in) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := in[:aes.BlockSize]
	in = in[aes.BlockSize:]
	if len(in) % aes.BlockSize != 0 {
		fmt.Println("len(in) mod aes.blocksize ==", len(in) % aes.BlockSize)
		return nil, false
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(in, in)
	out := unpad(in)
	if out == nil {
		fmt.Println("out == nil")
		return nil, false
	}
	return out, true	
}
func ConfirmData(pkt gopacket.Packet, SrcIP, DstIP []byte) bool {
	if pkt.SrcIP == SrcIP ||
		pkt.SrcIP == DstIP ||
		pkt.DstIP == SrcIP ||
		pkt.DstIP == DstIP {
		return true
	}
	return false
}
