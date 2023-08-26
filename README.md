Symmetric encryption

Signature = HMAC_SHA512(signatureSecret, stringToSign)

signatureSecret = AES128-Decrypt(clientSecret,decode-base-64(key))
    - key = encode-base-64(RandomKey(16 digit alphanumeric))
    - clientSecret = encode-base-64(RandomKey(32 digit alphanumeric))

StringToSign    = "HTTPMethod":"RelativeUrl":"AccessToken":"SHA-256(minify(RequestBody))":"CURRENT_TIMESTAMP"

AES128 yang digunakan : 
- CBC
- 16 bytes 


# references 
https://pkg.go.dev/github.com/andreburgaud/crypt2go/ecb
https://libraries.io/go/github.com%2Fandreburgaud%2Fcrypt2go
