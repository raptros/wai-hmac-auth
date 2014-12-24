{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module Network.Wai.Auth.HMAC where

import Control.Applicative
import Data.Foldable (Foldable, for_)
import Control.Monad (join, (>=>))
import Control.Monad.IO.Class
import qualified Data.ByteString as BS
import Data.IORef
import Data.Monoid
import Control.Monad.Trans.Reader (runReaderT)
import Control.Monad.Trans.Except (runExceptT)
import Control.Monad.Trans.State.Strict (execStateT)
import Control.Monad.Trans.Writer.Strict (runWriterT)
import qualified Control.Monad.Reader.Class as Mtl 
import qualified Control.Monad.Writer.Class as Mtl
import qualified Control.Monad.Error.Class as Mtl
import qualified Control.Monad.State.Class as Mtl
import qualified Data.ByteString.Base64.URL as B64
import Control.Monad.Loops (whileJust_)
import Crypto.Hash
import Crypto.MAC
import qualified Data.Sequence as S
import Data.Byteable (toBytes)

import Network.Wai
import Network.HTTP.Types.Header
import Network.HTTP.Types.URI (renderQuery)

-- * types

-- | a newtype wrapper for api keys
newtype ApiKey = ApiKey BS.ByteString deriving (Eq, Show)

-- | newtype wrapper for secret keys
newtype SecretKey = SecretKey BS.ByteString deriving (Eq, Show)

-- | specification for how the api key should be found in the request
data ApiKeySpec = 
    -- | look for a query parameter with the specified name
    QueryParamKey BS.ByteString |
    -- | look for the header with this name
    HeaderKey HeaderName
    deriving (Eq, Show)

-- | request configuration specifies how to perform hmac signing and
-- authentication on the request - i.e. where the api key will be found,
-- where the timestamp is stored, how the signature is added to the
-- request, and the hash algorithm to use.
data RequestConfig alg = RequestConfig {
    keySpec :: ApiKeySpec,
    timestampHeader :: HeaderName,
    signatureHeader :: HeaderName,
    hashAlgorithm :: alg
} deriving (Eq, Show)

-- | all of the way that signing or authentication can fail.
data AuthFailure =
    -- | the request does not have an api key value that fits the spec
    MissingApiKey ApiKeySpec |
    -- | the request does not have a timestamp header
    MissingTimestampHeader HeaderName |
    -- | the request does not have a signature header ('authenticate' only)
    MissingSignatureHeader HeaderName |
    -- | the signature was not url-safe base 64 encoded properly
    -- (authenticate only)
    SignatureBase64DecodeFailed String |
    -- | the signature was not a properly encoded hash digest (e.g. for the
    -- hash algorithm being used) (authenticate only)
    SignatureToDigestFailed |
    -- | the signature generated from the request did not match the
    -- signature contained within the reqest (authenticate only)
    HashMismatch
    deriving (Eq, Show)

-- ** constrain aliases

-- | a constraint alias for functions that need to access request
-- configuration
type HasReqConf alg m = (HashAlgorithm alg, Mtl.MonadReader (RequestConfig alg) m, Functor m)

-- | a constrain alias for functions that can fail
type AuthErrorsM m = (Mtl.MonadError AuthFailure m)

-- | a constraint alias for functions that save chunks of the request body
type WriteChunks m = (Mtl.MonadWriter (S.Seq BS.ByteString) m)

-- | a constrain alias for functions that perform incremental updates to
-- the hash value
type HmacState alg m = (Functor m, Applicative m, HashAlgorithm alg, Mtl.MonadState (HMACContext alg) m)

-- ** default setup

-- | default request configuration
--
-- @
-- defaultRequestConfig = 'RequestConfig' 'defaultApiKeySpec' "x-auth-timestamp" "x-auth-signature" 'SHA256'
-- @
defaultRequestConfig :: RequestConfig SHA256
defaultRequestConfig = RequestConfig defaultApiKeySpec "x-auth-timestamp" "x-auth-signature" SHA256


-- | default spec for getting the api key
--
-- @
-- defaultApiKeySpec = 'QueryParamKey' "apiKey"
-- @
defaultApiKeySpec :: ApiKeySpec
defaultApiKeySpec = QueryParamKey "apiKey"

-- * the tools 

-- | use this to get the api key from the request according to spec
getApiKey :: ApiKeySpec -> Request -> Maybe ApiKey
getApiKey (QueryParamKey k) = fmap ApiKey . join . lookup k . queryString
getApiKey (HeaderKey k) = fmap ApiKey . lookup k . requestHeaders

-- | authenticate the request according to the configuration and secret
-- key. if it succeeds, produces a request with a requestBody that will
-- produce the same chunk sequence as the original. if it fails, it will
-- explain why.
authenticate :: HashAlgorithm alg => RequestConfig alg -> Request -> SecretKey -> IO (Either AuthFailure Request)
authenticate conf req k = runReaderT (runExceptT (checkRequestHmac req k)) conf

-- | the operation performed by 'authenticate'
checkRequestHmac :: (MonadIO m, HasReqConf alg m, AuthErrorsM m) => Request -> SecretKey -> m Request
checkRequestHmac req key = do
    tsig <- getBase64DecodedSignature req
    p <- runWriterT $ hmacRequest req key
    sigCheck tsig p
    where
    sigCheck targetSig (actualSig, chunks)
        | targetSig == actualSig = rerunRequestBody req chunks
        | otherwise = Mtl.throwError HashMismatch

-- | signs a request in accordance with the config. mostly for testing.
signRequest :: HashAlgorithm alg => RequestConfig alg -> Request -> SecretKey -> IO (Either AuthFailure Request)
signRequest conf req k = runReaderT (runExceptT (addSignatureToRequest req k)) conf

-- | the operation performed by 'signRequest'
addSignatureToRequest :: (MonadIO m, HasReqConf alg m, AuthErrorsM m) => Request -> SecretKey -> m Request
addSignatureToRequest req key = do
    (genSig, chunks) <- runWriterT $ hmacRequest req key
    hname <- Mtl.reader signatureHeader
    let encSig = B64.encode (toBytes genSig)
        r' = addHeader req (hname, encSig)
    rerunRequestBody r' chunks

-- ** manipulate the request 

-- | constructs a new request with a 'requestBody' function that will
-- produce each item in the input sequence until the sequence is empty.
rerunRequestBody :: (Functor m, MonadIO m) => Request -> S.Seq BS.ByteString -> m Request
rerunRequestBody req = fmap (setRequestBody req . produceChunked) . liftIO . newIORef

-- | sets the request body to the IO action.
setRequestBody :: Request -> IO BS.ByteString -> Request
setRequestBody r b = r { requestBody = b }

-- | gets the next chunk from the referenced sequence, returning mempty if
-- it is already empty. (if it is not, then the IORef is updated to point
-- to the next item in the sequence).
produceChunked :: (Monoid a) => IORef (S.Seq a) -> IO a
produceChunked ref = readIORef ref >>= (handleChunks . S.viewl)
    where
    handleChunks S.EmptyL = pure mempty
    handleChunks (h S.:< t) = writeIORef ref t *> pure h

-- | add a header to a request (without checking for pre-existing headers)
addHeader :: Request -> (HeaderName, BS.ByteString) -> Request
addHeader r h = r { requestHeaders = h : requestHeaders r }

-- ** computing the request signature

-- | performs the full incremental hash/sign algorithm on the request and
-- returns the signature.
hmacRequest :: (MonadIO m, HasReqConf alg m, AuthErrorsM m, WriteChunks m) => Request -> SecretKey -> m (HMAC alg)
hmacRequest req = hmacRequestInit >=> execStateT (addHashComponents req) >=> return . hmacFinalize

-- | sets up the hash algorithm with the secret key
hmacRequestInit :: HasReqConf alg m => SecretKey -> m (HMACContext alg)
hmacRequestInit (SecretKey k) = flip hmacInitAlg k <$> Mtl.reader hashAlgorithm

-- *** adding stuff to the hash

-- | add all of the important components of the request to the hash 
-- 
-- - request method (newline)
-- - timestamp header (newline)
-- - api key (if necessary)
-- - raw path info 
-- - query params (with a question mark to separate from the path info)
-- - (newline)
-- - the body of the request
addHashComponents :: (MonadIO m, HasReqConf alg m, AuthErrorsM m, WriteChunks m, HmacState alg m) => Request -> m ()
addHashComponents = allRead [ 
    addToHash . requestMethod, addSep,
    addTimestampHeader, addSep, 
    ensureApiKeyIsAdded,
    addToHash . rawPathInfo,
    addToHash . renderQuery True . queryString, addSep,
    addBodyToHash
    ]
    where
    addSep = const (addToHash "\n")
    addTimestampHeader = getTimestampHeader >=> addToHash

-- | ensure the hash/signature will include the api key value according to
-- the spec - i.e. in either spec, this will fail the computation if the
-- key is not present according to spec; this function will have no further
-- effect for a query parameter key, but for a header key, it will add it
-- to the hash.
ensureApiKeyIsAdded :: (AuthErrorsM m, HasReqConf alg m, HmacState alg m) => Request -> m ()
ensureApiKeyIsAdded req =  Mtl.reader keySpec >>= (maybe <$> Mtl.throwError . MissingApiKey <*> actionForSpec <*> flip getApiKey req)
    where
    actionForSpec (QueryParamKey _) _ = return ()
    actionForSpec (HeaderKey _) (ApiKey k) = addToHash k >> addToHash "\n"

-- | keep getting chunks from the request and appending them to the hash
-- (and also storing them in the writer value) until there are no more chunks
addBodyToHash :: (MonadIO m, HmacState alg m, WriteChunks m) => Request -> m ()
addBodyToHash req = whileJust_ (getNextChunkForHash req) $ \c -> addToHash c *> Mtl.tell (S.singleton c)

-- | get the next chunk from the request body, if there is one
getNextChunkForHash :: (MonadIO m, Functor m) => Request -> m (Maybe BS.ByteString)
getNextChunkForHash = fmap (justUnless BS.null) . liftIO . requestBody

-- | add a value to the incremental hash
addToHash :: HmacState alg m => BS.ByteString -> m ()
addToHash = Mtl.modify . flip hmacUpdate

-- ** getting headers

-- | get the signature header value, decode it from base64 url encoding,
-- and then read it as a digest
getBase64DecodedSignature :: (HasReqConf alg m, AuthErrorsM m) => Request -> m (HMAC alg)
getBase64DecodedSignature = getSignatureHeader >=> 
                            either (Mtl.throwError . SignatureBase64DecodeFailed) return . B64.decode >=>
                            maybe (Mtl.throwError SignatureToDigestFailed) return . digestFromByteString >=>
                            return . HMAC

-- | get the header that should contain the timestamp
getTimestampHeader :: (AuthErrorsM m, HasReqConf alg m) => Request -> m BS.ByteString
getTimestampHeader = getHeader timestampHeader MissingTimestampHeader

-- | get the header that should contain the signature
getSignatureHeader :: (AuthErrorsM m, HasReqConf alg m) => Request -> m BS.ByteString
getSignatureHeader = getHeader signatureHeader MissingSignatureHeader

-- | get a header from the request; throw an error if it can't be found
getHeader :: (AuthErrorsM m, HasReqConf alg m) => (RequestConfig alg -> HeaderName) -> (HeaderName -> AuthFailure) -> Request -> m BS.ByteString
getHeader targetHeader err req = Mtl.reader targetHeader >>= \header ->
    maybe (Mtl.throwError (err header)) return $ lookup header (requestHeaders req)

-- * generic utilities

-- | return the value if the predicate of it is true
justWhen :: (a -> Bool) -> a -> Maybe a
justWhen p a = if p a then Just a else Nothing

-- | return the value if the predicate of it is false
justUnless :: (a -> Bool) -> a -> Maybe a
justUnless p a = if p a then Nothing else Just a

-- | calls every function in the data structure, and then traverses/folds
-- the contained actions.
allRead :: (Applicative m, Foldable t) => t (a -> m b) -> a -> m ()
allRead l v = for_ l  ($ v)
