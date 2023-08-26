package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
)

func GenerateStringToSign(data Data) string {

	hashedReqBody := Hash256(data.ReqBodyJson)
	log.Println("hashedReqBody : ", hashedReqBody)

	result := data.HttpMethod + ":" + data.RelativeUrl + ":" + data.AccessToken + ":" + hashedReqBody + data.TimeStamp

	log.Println("StringToSign : ", result)
	AESDecrypt(data)

	return result
}

func Hash256(reqBodyJson string) string {
	s := reqBodyJson
	h := sha256.New()
	h.Write([]byte(s))
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	return sha1_hash
}

func AESDecrypt(data Data) string {
	log.Println("Key sebelum decode base64 : ", data.Key)
	key, _ := base64.StdEncoding.DecodeString(data.Key)

	log.Println("Key setelah decode base64(binary) : ", key)
	log.Println("Key setelah decode base64(string) : ", string(key))
	// cipher.
	log.Println("clientSecret : ", data.ClientSecret)
	log.Println("len clientSecret : ", len(data.ClientSecret))
	cipherText, _ := base64.StdEncoding.DecodeString(data.ClientSecret)
	log.Printf("cipherText : %s\n", cipherText)

	//block, _ := aes.NewCipher(key)
	//log.Printf("block : %s\n", block)

	// if len(cipherText) < aes.BlockSize {
	// 	log.Println("invalid ciphertext block size")
	// }
	// len_data := len([]byte(data.ClientSecret))
	// datas := []byte(data.ClientSecret)
	// log.Println(len([]byte(data.ClientSecret)))
	// decrypted := make([]byte, len([]byte(data.ClientSecret)))
	// log.Println(decrypted)

	// size := 16

	// for bs, be := 0, size; bs < len_data; bs, be = bs+size, be+size {
	// 	cipher.Decrypt(decrypted[bs:be], datas[bs:be])
	// }

	//	log.Println(decrypted)
	//log.Println(string(decrypted))

	return ""
}

func ReadData() Data {
	// Open jsonFile
	jsonFile, err := os.Open("data.json")
	if err != nil {
		log.Fatalf("Error opening file: %s", err)
	}
	defer jsonFile.Close()
	log.Println("Successfully Opened data.json")

	// Read file content
	content, err := io.ReadAll(jsonFile)
	if err != nil {
		log.Fatalf("Error reading file: %s", err)
	}
	var data Data
	err = json.Unmarshal(content, &data)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON: %s", err)
	}
	return data
}

func main() {
	data := ReadData()
	GenerateStringToSign(data)

}
