Signature = HMAC_SHA512(signatureSecret, stringToSign)

signatureSecret = AES128-Decrypt(clientSecret,decode-base-64(key))

StringToSign    = "HTTPMethod":"RelativeUrl":"AccessToken":"SHA-256(minify(RequestBody))":"CURRENT_TIMESTAMP"