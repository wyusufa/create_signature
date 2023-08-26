Scenario : 
- There is an API that Client need to call to get clientSecret
- ClientSecret and Key will be used to create signature (Client that doesn't have key will always create wrong signature ) 
- Client send signature, httpMethod, relativeUrl, reqBodyJson(minify), and currentTimestamp  when send request to API 
- Backend will check whether the signature is correct or not. If it is wrong signature, the request will be rejected 

Signature = HMAC_SHA512(signatureSecret, stringToSign)

StringToSign    = "HTTPMethod":"RelativeUrl":"AccessToken":"SHA-256(minify(RequestBody))":"CURRENT_TIMESTAMP"

signatureSecret = RandomKey(32 digit alphanumeric)

Client get ClientSecret, to get signatureSecret, Client should do this : 
DecodeBase64(AES128-Decrypt(clientSecret,key))




