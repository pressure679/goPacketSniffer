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
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"bytes"
)

func main() {
	password := []byte("Induction")
	ssid := []byte("Coherer")
	fmt.Println("password     ", string(password))
	fmt.Println("salt str    ", string(ssid))
	pmk := string(HashPassword(password, ssid, 32))
	fmt.Printf("pmk          %x\n", pmk)
	var anonce string
	var snonce string
	var amac string
	var smac string
	msgnum := -1
	if handle, err := pcap.OpenOffline("wpa-Induction.pcap"); err != nil {
		panic(err)
	} else {
		pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range pktsrc.Packets() {
				if eapollayer := pkt.Layer(layers.LayerTypeEAPOL); eapollayer != nil {
				msgnum++
				if msgnum == 0 {
					amac = string(pkt.Data()[40:46])
					smac = string(pkt.Data()[28:34])
					anonce = string(pkt.Data()[73:105])
				} else if msgnum == 1 {
					snonce = string(pkt.Data()[73:105])
				}
			}
		}
		ptk := string(PTKGen(anonce, snonce, amac, smac, pmk))
		fmt.Println("ptk\t", ptk)
		for pkt := range pktsrc.Packets() {
			// Need to do something here
			data := pkt.Data()
			if dot11layer := pkt.Layer(layers.LayerTypeDot11); dot11layer != nil {
				dot11, _ := dot11layer.(*layers.Dot11)

				// data???
				decr, err := decrypt([]byte(ptk), data)
				if err != false {
					panic(err)
				}
				fmt.Println("dot11 proto:\n", dot11.Proto)
				fmt.Println("dot11 data:\n", decr)
			}
      if err != nil {
        panic(err)
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
			if applayer := pkt.ApplicationLayer(); applayer != nil {
				fmt.Println("payload:")
				fmt.Printf(hex.Dump(applayer.Payload()))
			}

		}
	}
}
func unpad(in []byte) []byte {
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
func decrypt(k, in []byte) ([]byte, bool) {
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
func clear(b []byte) {
  for i := 0; i < len(b); i++ {
    b[i] = 0;
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
		ptk = HashPassword(password, salt, 20)
		buff.Write(ptk)
	}
	ptk = buff.Bytes()
	return ptk
}
