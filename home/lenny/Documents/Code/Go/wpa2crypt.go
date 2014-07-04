package main
import (
  "crypto/aes"
  "crypto/cipher"
  "encoding/base64"
  "fmt"
)
var iv = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
func main() {
  keystr := []byte("1234") // 32 bytes
  plaintext := []byte("qwer")
	key := make([]byte, 16)
	copy(key[:], keystr)
  ciphertext := encrypt(key, plaintext)
  fmt.Printf("encrypted %x\n", ciphertext)
  result := decrypt(key, ciphertext)
  fmt.Printf("decrypted %s\n", result)
}
func pad(in []byte) []byte {
  padding := 16 - (len(in) % 16)
  if padding == 0 {
    padding = 16
  }
  for i := 0; i < padding; i++ {
    in = append(in, byte(padding))
  }
	fmt.Println("pad ", in)
  return in
}
func encrypt(k, in []byte) []byte {
  in = pad(in)
  if iv == nil {
    return nil
  }
  c, err := aes.NewCipher(k)
  if err != nil {
    return nil
  }
  cbc := cipher.NewCBCEncrypter(c, iv)
  cbc.CryptBlocks(in, in)
  return append(iv, in...)
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
	fmt.Println("unpaddded ", in[:len(in)-int(padding)])
  return in[:len(in)-int(padding)]
}
func decrypt(k, in []byte) []byte {
  if len(in) == 0 || len(in)%aes.BlockSize != 0 {
    return nil
  }
  c, err := aes.NewCipher(k)
  if err != nil {
    return nil
  }
  cbc := cipher.NewCBCDecrypter(c, in[:aes.BlockSize])
  cbc.CryptBlocks(in[aes.BlockSize:], in[aes.BlockSize:])
  out := unpad(in[aes.BlockSize:])
  if out == nil {
    return nil
  }
  return out
}
func encodebase64(b []byte) string {
  return base64.StdEncoding.EncodeToString(b)
}
func decodebase64(s string) []byte {
  data, err := base64.StdEncoding.DecodeString(s)
  if err != nil {
    panic(err)
  }
  return data
}
