wai-hmac-auth [![Build Status](https://travis-ci.org/raptros/wai-hmac-auth.svg?branch=master)](https://travis-ci.org/raptros/wai-hmac-auth) [![Hackage](https://img.shields.io/hackage/v/wai-hmac-auth.svg?style=flat)](http://hackage.haskell.org/package/wai-hmac-auth)
=============
this library provides functions for authenticating HMAC-signed requests in WAI
apps. in particular, it provides a function for extracting an api key from a
request according to configuration, and a function for verifying that a request
is correctly signed by a secret key, according to the configuration. it is
designed to be compatible with the Java library
[jersey-hmac-auth](https://github.com/bazaarvoice/jersey-hmac-auth), though
possibly more flexible.

how it signs
------------
the authenticate function (as well as the included signRequest function) in
effect extracts several elements from the request and concatentates them, and
hashes/signs the resulting value. i.e. it constructs the following value from
the request, and signs that value.

```
valueToSign = method + '\n' + 
              timestamp + '\n' + 
              (apiKey + '\n')? + 
              path + ('?' + query) + '\n' +
              body
```

* the method is added directly from the request record.
* the header name used to get the timestamp value can be configured. note that
  for now, no validation is done on this value; it is only required to be
  present in the request.
* the api key is only included explicitly if the configuration specifies that
  the api key is in a header. otherwise (if the api key is in a query
  parameter), it will be included anyway.
* the value of the path is whatever the application receives in the request
  record. this means that e.g. if the application is run in the context of a
  CGI executable, this may not be the same path that the client made the
  request to. the client will have to account for this when generating the
  signature.
* the query string is rendered from the queryString using the http-types
  function renderQuery. the wai-hmac-auth library does not modify these values,
  but the values received by the app may depend on the server and the
  middleware. the client will have to account for this properly.
* the entire request body is read, which is why authenticate produces a Request
  value when successful - this Request value has a requestBody value that will
  produce the same chunk sequence as the input request value.

the authenticate function also extracts the configured signature header and
attempts to decode it as a base64 url-encoded hash digest value as produced by
the configured hash function. this represents two possible authentication
failures.

finally, the authenticate function compares the passed signature to the
signature it generated and fails if they do not match.

how to use
----------
there are basically four steps for using this in your app.

* set up the configuration for how requests to your app will be signed
* when a request comes in, use getApiKey with your spec to find out who the
  requester is claiming to be
* load up the secret key associated with that identity (api key)
* use that secret key to run the authenticate function on the request
* send back appropriate responses for errors, otherwise continue with the
  transformed and authenticated request

for example:

```haskell
-- this would throw an error, i guess
demandApiKey :: IO a

-- 
informClientOfAuthenticationFailure :: AuthFailure -> IO a

-- imagine a function like this
getSecretOrFail :: ApiKey -> IO SecretKey

handleReq req = do
    apiKey <- getApiKey defaultApiKeySpec req >>= maybe demandApiKey return
    -- either get a caller reference or fail the request
    secretKey <- getSecretOrFail apiKey
    authRes <- authenticate defaultRequestConfig req secretKey
    req' <- either informClientOfAuthenticationFailure return authRes
    -- continue processing using the new request value.
```


