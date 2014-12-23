module Main where

import Control.Applicative
import Data.Byteable (toBytes)
import Crypto.Hash
import Test.Hspec
import Network.Wai 
import Network.Wai.Test (setPath)
import qualified Network.HTTP.Types as H
import qualified Data.ByteString as BS
import qualified Data.Sequence as S
import Network.Wai.Auth.HMAC
import Data.Maybe
import Data.Either
import qualified Data.ByteString.Base64.URL as B64

infixl 1 &
(&) :: a -> (a -> b) -> b
a & f = f a
{-# INLINE (&) #-}

setRequestMethod :: Request -> H.Method -> Request
setRequestMethod req method = req { requestMethod = method }

setRequestHeaders :: Request -> H.RequestHeaders -> Request
setRequestHeaders req headers = req { requestHeaders = headers }

removeRequestHeader :: H.HeaderName -> Request -> Request
removeRequestHeader targ req = setRequestHeaders req hdrs'
    where
    hdrs' = filter (not . (== targ) . fst) (requestHeaders req)

changeRequestHeader :: H.HeaderName -> BS.ByteString -> Request -> Request
changeRequestHeader targ newval req = setRequestHeaders req hdrs'
    where
    hdrs' = replacer <$> requestHeaders req
    replacer (n, v) = if n == targ then (n, newval) else (n, v)


mkRequest :: H.Method -> BS.ByteString -> H.RequestHeaders -> S.Seq BS.ByteString -> IO Request
mkRequest method path headers bodyChunks = defaultRequest `setRequestMethod` method `setRequestHeaders` headers `setPath` path `rerunRequestBody` bodyChunks

shouldBeLeft :: (Eq e, Show e, Show a) => Either e a -> e -> Expectation
shouldBeLeft e v = either (`shouldBe` v) (\r -> expectationFailure $ "expected: Left (" ++ show v ++ ")\n but got: " ++ show r) e

shouldJustSatisfy :: Show a => Maybe a -> (a -> Bool) -> Expectation
shouldJustSatisfy Nothing _ = expectationFailure "expected: Just a value\nbut got: Nothing"
shouldJustSatisfy (Just a) p = a `shouldSatisfy` p

failLeftOr :: Show e => Either e a -> (a -> Expectation) -> Expectation
failLeftOr e f = either (\l -> expectationFailure $ "expected: a Right value\nbut got: Left (" ++ show l ++ ")") f e

failNothing :: Maybe a -> (a -> Expectation) -> Expectation
failNothing m f = maybe (expectationFailure "expected: Just a value\nbut got: Nothing") f m


withSignedRequest :: HashAlgorithm alg => RequestConfig alg -> SecretKey -> IO Request -> (Request -> Expectation) -> Expectation
withSignedRequest conf k actReq f = do
    req <- actReq
    signRes <- signRequest conf req k
    failLeftOr signRes f

main :: IO ()
main = hspec $ do
    testGetApiKey
    testSignRequest
    testAuthenticate

testGetApiKey :: Spec
testGetApiKey = describe "getApiKey" $ do
    context "when using query param spec" $ do
        let spec = QueryParamKey "apiKey"
            getKey = getApiKey spec

        it "fails when no key is added" $ do
            req <- mkRequest H.methodGet "/" [] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "won't get key in header" $ do
            req <- mkRequest H.methodGet "/" [("apiKey", "somekey")] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "won't get key in different query param" $ do
            req <- mkRequest H.methodGet "/?passkey=somepass" [] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "is case sensitive" $ do
            req <- mkRequest H.methodGet "/?apikey=somepass" [] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "will get key in specified query param" $ do
            req <- mkRequest H.methodGet "/?apiKey=somepass" [] $ S.singleton "chunk"
            getKey req `shouldBe` Just (ApiKey "somepass")

    context "when using header spec" $ do
        let spec = HeaderKey "x-auth-apikey"
            getKey = getApiKey spec

        it "fails when no key is present" $ do
            req <- mkRequest H.methodGet "/" [] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "won't get key in query param" $ do
            req <- mkRequest H.methodGet "/?x-auth-apikey=somekey" [] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "won't get key in different header" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-passkey", "somekey")] $ S.singleton "chunk"
            getKey req `shouldBe` Nothing

        it "will get key in specified header" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-apikey", "somekey")] $ S.singleton "chunk"
            getKey req `shouldBe` Just (ApiKey "somekey")

        it "is NOT case sensitive" $ do
            req <- mkRequest H.methodGet "/" [("X-AUTH-APIKEY", "somekey")] $ S.singleton "chunk"
            getKey req `shouldBe` Just (ApiKey "somekey")

testSignRequest :: Spec
testSignRequest = describe "sign request" $ do
    context "when using a header api key" $ do
        let spec = HeaderKey "x-auth-apikey"
            conf = RequestConfig spec "x-auth-timestamp" "x-auth-signature" SHA256
            secretKey = SecretKey "test-key"
            confSign req = signRequest conf req secretKey

        it "demands the api key" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-timestamp", "2012-12-21T00:00:00Z")] $ S.singleton "chunk"
            signRes <- confSign req
            signRes `shouldBeLeft` MissingApiKey spec

        it "demands the timestamp" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-apikey", "somekey")] $ S.singleton "chunk"
            signRes <- confSign req
            signRes `shouldBeLeft` MissingTimestampHeader "x-auth-timestamp"

        it "produces a signed request" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-apikey", "somekey"), ("x-auth-timestamp", "2012-12-21T00:00:00Z")] $ S.singleton "chunk" S.|> "1 chunk2"
            signRes <- confSign req
            failLeftOr signRes $ \res -> 
                lookup "x-auth-signature" (requestHeaders res) `shouldSatisfy` isJust

        it "creates a base64-url encoded signature" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-apikey", "somekey"), ("x-auth-timestamp", "2012-12-21T00:00:00Z")] $ S.singleton "chunk" S.|> "1 chunk2"
            signRes <- confSign req
            failLeftOr signRes $ \res -> 
                failNothing (lookup "x-auth-signature" (requestHeaders res)) $ \hdr -> 
                    B64.decode hdr `shouldSatisfy` isRight

    context "when using a query param api key" $ do
        let spec = QueryParamKey "apiKey"
            conf = RequestConfig spec "x-auth-timestamp" "x-auth-signature" SHA256
            secretKey = SecretKey "test-key"
            confSign req = signRequest conf req secretKey

        it "demands the api key" $ do
            req <- mkRequest H.methodGet "/" [("x-auth-timestamp", "2012-12-21T00:00:00Z")] $ S.singleton "chunk"
            signRes <- confSign req
            signRes `shouldBeLeft` MissingApiKey spec

        it "demands the timestamp" $ do
            req <- mkRequest H.methodGet "/path?apiKey=somekey" [] $ S.singleton "chunk"
            signRes <- confSign req
            signRes `shouldBeLeft` MissingTimestampHeader "x-auth-timestamp"

        it "produces a signed request" $ do
            req <- mkRequest H.methodGet "/path?apiKey=somekey" [("x-auth-timestamp", "2012-12-21T00:00:00Z")] $ S.singleton "chunk"
            signRes <- confSign req
            failLeftOr signRes $ \res -> 
                lookup "x-auth-signature" (requestHeaders res) `shouldSatisfy` isJust

testAuthenticate :: Spec
testAuthenticate = describe "authenticate" $ do
    context "when using a query param api key" $ do
        let spec = QueryParamKey "apiKey"
            conf = RequestConfig spec "x-auth-timestamp" "x-auth-signature" SHA256
            secretKey = SecretKey "test-key"
            withSigned = withSignedRequest conf secretKey
            confAuthenticate req = authenticate conf req secretKey

        let simpleReq = mkRequest H.methodGet "/loc?apiKey=somekey" [("x-auth-timestamp", "2012-12-21T00:00:00Z")] (S.singleton "chunk" S.|> "1 chunk2")
        it "works with a simple signed request" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate sreq
            ares `shouldSatisfy` isRight

        it "complains about missing api key" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ setPath sreq "/loc"
            ares `shouldBeLeft` MissingApiKey spec

        it "complains about missing timestamp" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ removeRequestHeader "x-auth-timestamp" sreq
            ares `shouldBeLeft` MissingTimestampHeader "x-auth-timestamp"

        it "complains about missing signature" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ removeRequestHeader "x-auth-signature" sreq
            ares `shouldBeLeft` MissingSignatureHeader "x-auth-signature"

        it "complains about incorrectly-encoded signature" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ changeRequestHeader "x-auth-signature" "fake.it" sreq
            putStrLn (show ares)
            ares `shouldBeLeft` SignatureBase64DecodeFailed "invalid padding"
            ares2 <- confAuthenticate $ changeRequestHeader "x-auth-signature" (B64.encode "invalid") sreq
            ares2 `shouldBeLeft` SignatureToDigestFailed

        it "complains if the signature does not match" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ changeRequestHeader "x-auth-signature" (B64.encode $ toBytes $ (hash "what" :: Digest SHA256)) sreq
            ares `shouldBeLeft` HashMismatch

        context "when a request is already signed" $ do
            it "fails if the api key param changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate $ setPath sreq "/loc?apiKey=otherkey"
                ares `shouldBeLeft` HashMismatch

    context "when using a header api key" $ do
        let spec = HeaderKey "x-auth-apikey"
            conf = RequestConfig spec "x-auth-timestamp" "x-auth-signature" SHA256
            secretKey = SecretKey "test-key"
            withSigned = withSignedRequest conf secretKey
            confAuthenticate req = authenticate conf req secretKey

        let simpleReq = mkRequest H.methodGet "/loc" [("x-auth-apikey", "somekey"), ("x-auth-timestamp", "2012-12-21T00:00:00Z")] (S.singleton "chunk" S.|> "1 chunk2")
        it "works with a simple signed request" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate sreq
            ares `shouldSatisfy` isRight

        it "complains about missing api key header" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ removeRequestHeader "x-auth-apikey" sreq
            ares `shouldBeLeft` MissingApiKey spec

        it "complains about missing timestamp" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ removeRequestHeader "x-auth-timestamp" sreq
            ares `shouldBeLeft` MissingTimestampHeader "x-auth-timestamp"

        it "complains about missing signature" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ removeRequestHeader "x-auth-signature" sreq
            ares `shouldBeLeft` MissingSignatureHeader "x-auth-signature"

        it "complains about incorrectly-encoded signature" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ changeRequestHeader "x-auth-signature" "fake.it" sreq
            putStrLn (show ares)
            ares `shouldBeLeft` SignatureBase64DecodeFailed "invalid padding"
            ares2 <- confAuthenticate $ changeRequestHeader "x-auth-signature" (B64.encode "invalid") sreq
            ares2 `shouldBeLeft` SignatureToDigestFailed

        it "complains if the signature does not match" $ withSigned simpleReq $ \sreq -> do
            ares <- confAuthenticate $ changeRequestHeader "x-auth-signature" (B64.encode $ toBytes $ (hash "what" :: Digest SHA256)) sreq
            ares `shouldBeLeft` HashMismatch

        context "when a request is already signed" $ do
            it "fails if the method changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate $ setRequestMethod sreq "PUT" 
                ares `shouldBeLeft` HashMismatch

            it "fails if the path changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate $ setPath sreq "/pathnew"
                ares `shouldBeLeft` HashMismatch

            it "fails if the query string changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate $ setPath sreq "/loc?query=value"
                ares `shouldBeLeft` HashMismatch

            it "fails if the timestamp changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate $ changeRequestHeader "x-auth-timestamp" "faketime" sreq
                ares `shouldBeLeft` HashMismatch

            it "fails if the api key header changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate $ changeRequestHeader "x-auth-apikey" "otherkey" sreq
                ares `shouldBeLeft` HashMismatch

            it "fails if the body changes" $ withSigned simpleReq $ \sreq -> do
                ares <- confAuthenticate =<< rerunRequestBody sreq (S.singleton "chunk0 ")
                ares `shouldBeLeft` HashMismatch
