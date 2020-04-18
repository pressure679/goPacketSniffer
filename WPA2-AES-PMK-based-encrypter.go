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

// It should return the same PTK as in http://stackoverflow.com/questions/12018920/wpa-handshake-with-python-hashing-difficulties
// but I guess something is wrong;
// I abandon this project from now on, everything else is ready, the PTK just needs to be made (you can use another software to make this)
// maybe the null byte for the passwordstr is not made right
// maybe the keylen for HashPassword is right (128 bit TKIP and 4 iterations, 256 bit for CCMP and 3 iterations)
// maybe my min() and max() does not return the same as Python's
// 
// desired ptk[0:16]:
// bf49 a95f 0494 f444 2716 2f38 696e f8b6

package main
import (
	"fmt"
	// "golang.org/x/crypto/sha1"
	// "github.com/golang/crypto/pbkdf2"
	"encoding/base64"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/aes"
	"golang.org/x/crypto/pbkdf2"
	"flag"
	"io/ioutil"
	"os"
	"io"
	"crypto/rand"
	"errors"
)
func main() {
	passphrase  := "10zZz10ZZzZ"
	ssid        := "Netgear 2/158" 

	pmk := pbkdf2.Key([]byte(passphrase), []byte(ssid), 4096, 32, sha1.New)
	fmt.Println("Pairwise Master key:")
	fmt.Println("* Hex:")
	for x := 0; x < len(pmk); x++ {
		if x % 16 == 0 {
			if x > 0 { fmt.Println() }
			fmt.Print("  ")
		}
		if x % 2 == 0 {
			fmt.Printf("%x ", pmk[x:x + 2])
		}
	}
	fmt.Println()
	fmt.Println("* Bytes:")
	fmt.Println(" ", pmk)
	fmt.Println("* String:")
	fmt.Println(" ", string(pmk))
	file := flag.String("file", "", "the file to read data from to encrypt with a simulation of assymmetric keys like in WPA - using AES, SHA1, and MD5 - the method used ix 16 byte PMK xor")
	flag.Parse()
	osFile, err := os.Open(*file)
	if err != nil { panic(err) }
	data, err := ioutil.ReadFile(osFile.Name())
	if err = osFile.Close(); err != nil { panic(err) }
	datawithpadding, err := PadToBlockSize(string(data))
	if err != nil { panic(err) }
	encrypted, err := encrypt(pmk, datawithpadding)
	if err != nil { panic(err) }
	fmt.Println("Encrypted data:")
	fmt.Println("* String:")
	fmt.Println(" ", encrypted)
	// fmt.Println("* Hex:")
	// fmt.Println(hex.Dump(encrypted)
	// fmt.Println("* Bytes:")
	// fmt.Println([]byte(encrypted))
	decrypted, err := decrypt(pmk, string(encrypted))
	fmt.Println("Decrypted data:")
	fmt.Println("* String:")
	fmt.Println(" ", decrypted)
	// fmt.Println("* Hex:")
	// fmt.Println(hex.Dump(decrypted)
	// fmt.Println("* Bytes:")
	// fmt.Println([]byte(decrypted))
}

// From https://stackoverflow.com/questions/50762009/aes-256-cbc-encryption-not-matching-between-golang-and-node-php/50762567
func PadToBlockSize(input string) (padding string, err error) {
	paddingNeeded := aes.BlockSize - (len(input) % aes.BlockSize)
	if paddingNeeded >= 256 { return "", errors.New("aes.BlockSize - len(input) % aes.BlockSize >= 256") }

	if paddingNeeded == 0 { paddingNeeded = aes.BlockSize }

	// Inefficient, once again, this is an example only!
	for i := 0; i < paddingNeeded; i++ {
		input += string(byte(paddingNeeded))
	}
	return input, nil
}

// From https://gist.github.com/mickelsonm/e1bf365a149f3fe59119
func encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil { return }

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil { return }

	// stream := cipher.NewCFBEncrypter(block, iv)
	blockmode := cipher.NewCBCEncrypter(block, iv)
	// stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
	blockmode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}
func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil { return }

	block, err := aes.NewCipher(key)
	if err != nil { return }

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// stream := cipher.NewCFBDecrypter(block, iv)
	blockmode := cipher.NewCBCDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	// stream.XORKeyStream(cipherText, cipherText)
	blockmode.CryptBlocks(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}
