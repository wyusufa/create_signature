package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
)

func GenerateStringToSign(data Data) string {
	hashedReqBody := Hash256(data.ReqBodyJson)
	log.Println("Hashed Request Body : ", hashedReqBody)
	result := data.HttpMethod + ":" + data.RelativeUrl + ":" + data.AccessToken + ":" + hashedReqBody + data.TimeStamp
	log.Println("String To Sign : ", result)
	return result
}

func GenerateRandomKey(digit int) string {
	log.Println("Start Generate Random Alphanumeric")
	uuid := uuid.NewString()
	x := strings.Replace(uuid, "-", "", -1)
	result := x[0:digit]
	log.Println("Random key : ", result)
	log.Println("digit : ", digit)
	log.Println("End Generate Random Alphanumeric")
	return result
}

func AES128Encrypt(signatureSecret, decodedKey string) string {
	log.Println("Data to encrypt : ", signatureSecret)

	text := []byte(signatureSecret)
	key := []byte(decodedKey)

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	x := string(gcm.Seal(nonce, nonce, text, nil))
	return EncodeBase64(x)
}

func AES128Decrypt(clientSecret, decodedKey string) string {
	log.Println("Start AES128Decrypt")

	key := []byte(decodedKey)
	ciphertext := []byte(DecodeBase64(clientSecret))

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
	}
	log.Println("Decrypt Result : ", string(plaintext))
	log.Println("End AES128Decrypt")
	return string(plaintext)
}

func HMAC_SHA256(signatureSecret, stringToSign string) string {
	log.Println("Start Create Signature")
	secret := signatureSecret
	data := stringToSign

	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	log.Println("Signature: " + sha)
	log.Println("End Create Signature")
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
	data := ReadData()
	clientSecret := AES128Encrypt(GenerateRandomKey(32), DecodeBase64(data.Key))
	signatureSecret := AES128Decrypt(clientSecret, DecodeBase64(data.Key))
	HMAC_SHA256(signatureSecret, GenerateStringToSign(data))
}
