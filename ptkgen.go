// This software is for intended for WPA-2 cracking, with or without ARP Poisoning. - Not yet finished
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

// This program is supposed to do the same as the code from here
// http://stackoverflow.com/questions/12018920/wpa-handshake-with-python-hashing-difficulties
// But something is wrong with the ptkgen function
// 
// I've also used http://www.perlmonks.org/?node_id=1090649 as example code

package main

import (
	"fmt"
	"crypto/sha1"
	"crypto/pbkdf2"
	"bytes"
)

func HashPassword(password, salt []byte, keylen int) []byte {
  return pbkdf2.Key(password, salt, 4096, keylen, sha1.New)
}

// Something wrong with ptkgen, doesn't generate desired ptk
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

func printHexArray(hexarr string) {
	for i := 0; i < len(hexarr) / 2; i++ {
		if i % 8 == 0 {
			fmt.Printf("\n")
		}
		u := i * 2
		fmt.Printf("%x ", hexarr[u:u+2])
	}	
	fmt.Printf("\n\n")
}

func main() {
	desiredpmk := "01b8 09f9 ab2f b5dc 4798 4f52 fb2d 112e\n13d8 4ccb 6b86 d4a7 193e c529 9f85 1c48"
	desiredptk := "bf49 a95f 0494 f444 2716 2f38 696e f8b6\n428b cf8b a3c6 f0d7 245a d314 a14c 0d18\nefd6 38aa e653 c908 a7ab c648 0a7f 4068\n2479 c970 8aaa abc3 eb7e da28 9d06 d535"

	password := []byte("10zZz10ZZzZ")
	ssid := []byte("Netgear 2/158")
	anonce := "61c9a3f5cdcdf5fae5fd760836b8008c863aa2317022c7a202434554fb38452b"
	snonce := "60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318"
	amac := "001e2ae0bdd0"
	smac := "cc08e0620bc8"

	fmt.Println("password     ", string(password))
	fmt.Println("salt str    ", string(ssid))

	pmk := string(HashPassword(password, ssid, 32))
	ptk := string(PTKGen(anonce, snonce, amac, smac, pmk))

	fmt.Printf("\ngenerated pmk:")
	printHexArray(pmk)
	fmt.Printf("generated ptk:")
	printHexArray(ptk)

	fmt.Println("desired pmk:\n", desiredpmk)
	fmt.Println("\ndesired ptk:\n", desiredptk)
}
