Symmetric encryption

- User get accessToken and clientSecret 
- User has to create signature 
- to create signature, User has to have signatureSecret
- to create signatureSecret, User has to have key 
- User that doesn't have key will always create wrong signature 

Signature = HMAC_SHA512(signatureSecret, stringToSign)

Sequences : 
1. signatureSecret = RandomKey(32 digit alphanumeric)
2. key = RandomKey(16 digit alphanumeric)
3. clientSecret = EncodeBase64(AES128-Encrypt(signatureSecret,key))
4. signatureSecret = DecodeBase64(AES128-Decrypt(clientSecret,key))


StringToSign    = "HTTPMethod":"RelativeUrl":"AccessToken":"SHA-256(minify(RequestBody))":"CURRENT_TIMESTAMP"


# references 
https://pkg.go.dev/github.com/andreburgaud/crypt2go/ecb
https://libraries.io/go/github.com%2Fandreburgaud%2Fcrypt2go
