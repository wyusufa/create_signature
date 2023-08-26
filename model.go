package main

type Data struct {
	AccessToken  string `json:"accessToken"`
	ClientSecret string `json:"clientSecret"`
	HttpMethod   string `json:"httpMethod"`
	RelativeUrl  string `json:"relativeUrl"`
	ReqBodyJson  string `json:"reqBodyJson"`
	TimeStamp    string `json:"timeStamp"`
	Key          string `json:"key"`
}
