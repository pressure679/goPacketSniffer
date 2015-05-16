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
	//"crypto/hmac"
	"crypto/sha1"
	"crypto/pbkdf2"
	"encoding/hex"
	"bytes"
)
func main() {
	passphrase  := "10zZz10ZZzZ"
	ssid        := "Netgear 2/158" 
	a           := "Pairwise key expansion" 
	apmac       := "001e2ae0bdd0"
	clientmac   := "cc08e0620bc8"
	anonce      := "61c9a3f5cdcdf5fae5fd760836b8008c863aa2317022c7a202434554fb38452b"
	snonce      := "60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318"
	//b           := min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)
	// data        := "0103005ffe010900200000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	onemac := min(apmac, clientmac)
	twomac := max(apmac, clientmac)
	onenonce := min(anonce, snonce)
	twononce := max(anonce, snonce)
	b := onemac + twomac + onenonce + twononce

	pmk := pbkdf2.Key([]byte(passphrase), []byte(ssid), 4096, 32, sha1.New)
	ptk := CustomPRF512(string(pmk), a, b, ssid)
	for x := 0; x < len(ptk); x++ {
		if x % 16 == 0 {
			fmt.Println()
		}
		if x % 2 == 0 {
			fmt.Printf("%x ", ptk[x:x + 2])
		}
	}
}
func CustomPRF512(key, a, b, ssid string) []byte {
	var ptk []byte
	var buff bytes.Buffer
	nullbyte := []byte{0}
	for i := 0; i < 5; i++ {
		passwordstr := "Pairwise key expansion" + string(nullbyte) + b + string(i)
		password := []byte(passwordstr)

		mysha1 := sha1.New()
		mysha1.Write([]byte(key))
		ptk1 := HashPassword(password, []byte(ssid))
		
		buff.Write(ptk1)
	}
	ptk = buff.Bytes()
	return ptk
}
func HashPassword(password, salt []byte) []byte {
  defer clear(password)
  return pbkdf2.Key(password, salt, 4096, 16, sha1.New)
}
func checkerr(err error) {
	if err != nil {
		panic(err)
	}
}
func min(one, two string) string {
	src0 := []byte(one)
	dst0 := make([]byte, hex.DecodedLen(len(src0)))
	oneLen, err0 := hex.Decode(dst0, src0)
	checkerr(err0)

	src1 := []byte(two)
	dst1 := make([]byte, hex.DecodedLen(len(src1)))
	twoLen, err1 := hex.Decode(dst1, src1)
	checkerr(err1)

	if oneLen < twoLen {
		return one
	}
	return two
}
func max(one, two string) string {
	src0 := []byte(one)
	dst0 := make([]byte, hex.DecodedLen(len(src0)))
	oneLen, err0 := hex.Decode(dst0, src0)
	checkerr(err0)

	src1 := []byte(two)
	dst1 := make([]byte, hex.DecodedLen(len(src1)))
	twoLen, err1 := hex.Decode(dst1, src1)
	checkerr(err1)

	if oneLen < twoLen {
		return one
	}
	return two
}
func clear(b []byte) {
  for i := 0; i < len(b); i++ {
    b[i] = 0;
  }
}
