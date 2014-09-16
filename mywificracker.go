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
	// "encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"bytes"
	"flag"
)

// anonce, snonce, amac, smac is retrieved.
	// ssid, file & password is entered as argument.
	// pmk, pairwise master key, is derived from
	// password with pbkdf2.

	// ptkgen method at line 192
	// does not work.
	// use my pyptkgen.py

// ptk is entered at line 90.

func getPkts(file string) {
	// open offline capture with
	// file as source.
	handle, err := pcap.OpenOffline(string(file))
	if err != nil { panic(err) }
	pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	return pktsrc.Packets()
}

func main() {
	password := flag.String("password", "", "The password or key for decryption")
	ssid := flag.String("ssid", "", "The essid or key for decryption")
	file := flag.String("file", "", "The file to read data from")
	flag.Parse()

 	// pmk - pairwise master key
	// is dervied from password with
	// ssid as salt using pbkdf2.
	pmkbyte := HashPassword(password, ssid, 32)
	pmk := string(pmkbyte)

	// print objects
	fmt.Println("salt str:   ", *ssid)
	fmt.Println("password:   ", *password)
	fmt.Printf("file:        %s\n", *file)
	fmt.Printf("pmk:         %x\n", pmk)

	// objects that are retrieved from EAPOL
	// packets in pcap file.
	// These are used to derive ptk
	// from pmk, which is derived from
	// password with pbkdf2.
	var anonce string
	var snonce string
	var amac string
	var smac string
	var msgnum int = -1

	// open offline capture with
	// file as source.
	pkts := getPkts(*file)

	// loop through all packets in pcap file to retrieve
	// nonces & macs to derive ptk from pmk, which is
	// derived from password with pbkdf2.

	for pkt := range pkts {

	// extract following:
	// anonce, snonce,
	// amac, snonce,
	// extract ssid yourself,
	// or with my pcapreader.go
		if EAPOLLayer := pkt.Layer(layers.LayerTypeEAPOL); EAPOLLayer != nil {
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

	// here you write ptk
	ptk := []byte("1602d720fc46d33ae77386cde5718a4d0efe5c18cdf9cba42b606424fa992ca0a69e3e67a6d9f080")
	fmt.Printf("ptk length:   %d\nptk          %s\namac:        %x\nsmac:        %x\nanonce:      %x\nsnonce:      %x\n", len(ptk), string(ptk), amac, smac, anonce, snonce)

	pkts := getPkts(*file)

	// loop through all packets in pcap file for decrypt.
	for pkt := range pkts {
		data := pkt.Data()
		fmt.Printf("%s\n", string(data))

		// decrypt the next 5 layers in each "if" statements
		// with aes.cbc pkcs#7 unpadding.
		// create ptk from pmk, nonces and macs yourself.
		// ptkgen method does not work.
		if Dot11Layer := pkt.Layer(layers.LayerTypeDot11); Dot11Layer != nil {
			dot11, _ := Dot11Layer.(*layers.Dot11)

			// data???
			fmt.Println("dot11 proto:\n", dot11.Proto)
			fmt.Printf("dot11 contents:\n%s\n", dot11.Contents)
			fmt.Printf("dot11 payload:\n%s\n", dot11.Payload)
			fmt.Printf("dump:\n%s\n", pkt.Dump())
			decr, _ := decrypt(ptk, data)
			fmt.Println("dot11 data decrypted:\n", decr)
		}
		if Dot11DataLayer := pkt.Layer(layers.LayerTypeDot11Data); Dot11DataLayer != nil {
			dot11data, _ := Dot11DataLayer.(*layers.Dot11Data)
			payload := dot11data.BaseLayer.Payload
			contents := dot11data.BaseLayer.Contents
			fmt.Println("dot11data payload:\n", payload)
			fmt.Println("dot11data contents:\n", contents)
			decr0, _ := decrypt(ptk, payload)
			fmt.Println("dot11data payload:\n", decr0)
			decr1, _ := decrypt(ptk, contents)
			fmt.Println("dot11data content:\n", decr1)
		}
		if IPLayer := pkt.Layer(layers.LayerTypeIPv4); IPLayer != nil {
			ip, _ := IPLayer.(*layers.IPv4)
			fmt.Printf("%s\t\t%d\t%s\n", ip.SrcIP.String(), ip.TTL, ip.DstIP.String())
		}
		if TCPLayer := pkt.Layer(layers.LayerTypeTCP); TCPLayer != nil {
			tcp, _ := TCPLayer.(*layers.TCP)
			fmt.Printf("TCP: %d\t\t%d\t%d\n", tcp.SrcPort, tcp.DstPort)
		} else if UDPLayer := pkt.Layer(layers.LayerTypeUDP); UDPLayer != nil {
			udp, _ := UDPLayer.(*layers.UDP)
			fmt.Printf("TCP: %d\t\t%d\t%d\n", udp.SrcPort, udp.DstPort)
		}
	}
}
// pkcs#7 unpadding
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
// aes-cbc decrypter with pkcs#7 unpadding
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
// for clearing pmk, ssid & password you've provided,
// but not used atm.
func clear(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0;
	}
}
// create pmk from password with pbkdf2
func HashPassword(password, salt []byte, keylen int) []byte {
	return pbkdf2.Key(password, salt, 4096, keylen, sha1.New)
}
// This ptk gen does not work correctly,
// instead just write ptk at line 91.
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
