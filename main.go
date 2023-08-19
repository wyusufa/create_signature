package main

import (
	"fmt"
	"os"
)

type data struct {
	AccessToken  string `json:"accessToken"`
	ClientSecret string `json:"clientSecret"`
	HttpMethod   string `json:"httpMethod"`
	RelativeUrl  string `json:"relativeUrl"`
	ReqBodyJson  string `json:"reqBodyJson"`
	TimeStamp    string `json:"timeStamp"`
	Key          string `json:"key"`
}

func main() {
	// Open our jsonFile
	jsonFile, err := os.Open("data.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened data.json")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
}
