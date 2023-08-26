package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
)

func GenerateStringToSign(data Data) string {
	hashedReqBody := Hash256(data.ReqBodyJson)
	log.Println("hashedReqBody : ", hashedReqBody)
	result := data.HttpMethod + ":" + data.RelativeUrl + ":" + data.AccessToken + ":" + hashedReqBody + data.TimeStamp
	log.Println("StringToSign : ", result)
	return result
}

func GenerateRandomKey(digit int) string {
	log.Print("Start Generate Random Alphanumeric")
	uuid := uuid.NewString()
	x := strings.Replace(uuid, "-", "", -1)
	result := x[0:digit]
	encodedResult := EncodeBase64(result)
	log.Print("End Generate Random Alphanumeric")
	return encodedResult
}

func AES128Encrypt(clientSecret, decodedKey string) string {
	//GCM
	return ""
}

func AES128Decrypt(clientSecret, decodedKey string) string {
	//GCM
	return ""
}

func HMAC_SHA512(signatureSecret, stringToSign string) string {
	return ""
}

func Hash256(reqBodyJson string) string {
	s := reqBodyJson
	h := sha256.New()
	h.Write([]byte(s))
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	return sha1_hash
}

func DecodeBase64(x string) string {
	log.Println("Start DecodeBase64")
	log.Println("InputData : ", x)
	decodedByte, _ := base64.StdEncoding.DecodeString(x)
	decodedString := string(decodedByte)
	log.Println("DecodedData : ", decodedString)
	log.Println("End DecodeBase64")
	return decodedString
}

func EncodeBase64(x string) string {
	log.Println("Start EncodedBase64")
	log.Println("InputData : ", x)
	encodedString := base64.StdEncoding.EncodeToString([]byte(x))
	log.Println("EncodedData : ", encodedString)
	log.Println("End EncodedBase64")
	return encodedString
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
	//data := ReadData()
	//GenerateStringToSign(data)
	result := GenerateRandomKey(16)
	DecodeBase64(result)
}
