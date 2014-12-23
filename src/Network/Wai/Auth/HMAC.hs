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

newtype ApiKey = ApiKey BS.ByteString deriving (Eq, Show)

newtype SecretKey = SecretKey BS.ByteString deriving (Eq, Show)

data ApiKeySpec = 
    QueryParamKey BS.ByteString |
    HeaderKey HeaderName
    deriving (Eq, Show)

data RequestConfig alg = RequestConfig {
    keySpec :: ApiKeySpec,
    timestampHeader :: HeaderName,
    signatureHeader :: HeaderName,
    hashAlgorithm :: alg
} deriving (Eq, Show)

data AuthFailure =
    MissingApiKey ApiKeySpec |
    MissingTimestampHeader HeaderName |
    MissingSignatureHeader HeaderName |
    SignatureBase64DecodeFailed String |
    SignatureToDigestFailed |
    HashMismatch
    deriving (Eq, Show)

-- ** constrain aliases

type HasReqConf alg m = (HashAlgorithm alg, Mtl.MonadReader (RequestConfig alg) m, Functor m)

type AuthErrorsM m = (Mtl.MonadError AuthFailure m)

type WriteChunks m = (Mtl.MonadWriter (S.Seq BS.ByteString) m)

type HmacState alg m = (Functor m, Applicative m, HashAlgorithm alg, Mtl.MonadState (HMACContext alg) m)

-- ** default setup

defaultRequestConfig :: RequestConfig SHA256
defaultRequestConfig = RequestConfig defaultApiKeySpec "x-auth-timestamp" "authorization" SHA256

defaultApiKeySpec :: ApiKeySpec
defaultApiKeySpec = HeaderKey "x-auth-key"

-- * the tools 

getApiKey :: ApiKeySpec -> Request -> Maybe ApiKey
getApiKey (QueryParamKey k) = fmap ApiKey . join . lookup k . queryString
getApiKey (HeaderKey k) = fmap ApiKey . lookup k . requestHeaders

authenticate :: HashAlgorithm alg => RequestConfig alg -> Request -> SecretKey -> IO (Either AuthFailure Request)
authenticate conf req k = runReaderT (runExceptT (checkRequestHmac req k)) conf

checkRequestHmac :: (MonadIO m, HasReqConf alg m, AuthErrorsM m) => Request -> SecretKey -> m Request
checkRequestHmac req key = do
    tsig <- getBase64DecodedSignature req
    p <- runWriterT $ hmacRequest req key
    sigCheck tsig p
    where
    sigCheck targetSig (actualSig, chunks)
        | targetSig == actualSig = rerunRequestBody req chunks
        | otherwise = Mtl.throwError HashMismatch

-- | mostly for testing
signRequest :: HashAlgorithm alg => RequestConfig alg -> Request -> SecretKey -> IO (Either AuthFailure Request)
signRequest conf req k = runReaderT (runExceptT (addSignatureToRequest req k)) conf

addSignatureToRequest :: (MonadIO m, HasReqConf alg m, AuthErrorsM m) => Request -> SecretKey -> m Request
addSignatureToRequest req key = do
    (genSig, chunks) <- runWriterT $ hmacRequest req key
    hname <- Mtl.reader signatureHeader
    let encSig = B64.encode (toBytes genSig)
        r' = addHeader req (hname, encSig)
    rerunRequestBody r' chunks

-- ** manipulate the request 

rerunRequestBody :: (Functor m, MonadIO m) => Request -> S.Seq BS.ByteString -> m Request
rerunRequestBody req = fmap (setRequestBody req . produceChunked) . liftIO . newIORef

setRequestBody :: Request -> IO BS.ByteString -> Request
setRequestBody r b = r { requestBody = b }

produceChunked :: (Monoid a) => IORef (S.Seq a) -> IO a
produceChunked ref = readIORef ref >>= (handleChunks . S.viewl)
    where
    handleChunks S.EmptyL = pure mempty
    handleChunks (h S.:< t) = writeIORef ref t *> pure h

addHeader :: Request -> (HeaderName, BS.ByteString) -> Request
addHeader r h = r { requestHeaders = h : requestHeaders r }

-- ** computing the request signature

hmacRequest :: (MonadIO m, HasReqConf alg m, AuthErrorsM m, WriteChunks m) => Request -> SecretKey -> m (HMAC alg)
hmacRequest req = hmacRequestInit >=> execStateT (addHashComponents req) >=> return . hmacFinalize

hmacRequestInit :: HasReqConf alg m => SecretKey -> m (HMACContext alg)
hmacRequestInit (SecretKey k) = flip hmacInitAlg k <$> Mtl.reader hashAlgorithm

-- *** adding stuff to the hash

addHashComponents :: (MonadIO m, HasReqConf alg m, AuthErrorsM m, WriteChunks m, HmacState alg m) => Request -> m ()
addHashComponents = allRead [ 
    addToHash . requestMethod, addSep,
    addTimestampHeader, addSep, 
    ensureApiKeyIsAdded,
    addToHash . rawPathInfo, addSep,
    addToHash . rawPathInfo,
    --todo: proper formatting of query params
    addToHash . renderQuery True . queryString, addSep,
    addBodyToHash
    ]
    where
    addSep = const (addToHash "\n")
    addTimestampHeader = getTimestampHeader >=> addToHash

ensureApiKeyIsAdded :: (AuthErrorsM m, HasReqConf alg m, HmacState alg m) => Request -> m ()
ensureApiKeyIsAdded req =  Mtl.reader keySpec >>= (maybe <$> Mtl.throwError . MissingApiKey <*> actionForSpec <*> flip getApiKey req)
    where
    actionForSpec (QueryParamKey _) _ = return ()
    actionForSpec (HeaderKey _) (ApiKey k) = addToHash k >> addToHash "\n"

addBodyToHash :: (MonadIO m, HmacState alg m, WriteChunks m) => Request -> m ()
addBodyToHash req = whileJust_ (getNextChunkForHash req) $ \c -> addToHash c *> Mtl.tell (S.singleton c)

getNextChunkForHash :: (MonadIO m, Functor m) => Request -> m (Maybe BS.ByteString)
getNextChunkForHash = fmap (justUnless BS.null) . liftIO . requestBody

addToHash :: HmacState alg m => BS.ByteString -> m ()
addToHash = Mtl.modify . flip hmacUpdate

-- ** getting headers

getBase64DecodedSignature :: (HasReqConf alg m, AuthErrorsM m) => Request -> m (HMAC alg)
getBase64DecodedSignature = getSignatureHeader >=> 
                            either (Mtl.throwError . SignatureBase64DecodeFailed) return . B64.decode >=>
                            maybe (Mtl.throwError SignatureToDigestFailed) return . digestFromByteString >=>
                            return . HMAC

getTimestampHeader :: (AuthErrorsM m, HasReqConf alg m) => Request -> m BS.ByteString
getTimestampHeader = getHeader timestampHeader MissingTimestampHeader

getSignatureHeader :: (AuthErrorsM m, HasReqConf alg m) => Request -> m BS.ByteString
getSignatureHeader = getHeader signatureHeader MissingSignatureHeader

getHeader :: (AuthErrorsM m, HasReqConf alg m) => (RequestConfig alg -> HeaderName) -> (HeaderName -> AuthFailure) -> Request -> m BS.ByteString
getHeader targetHeader err req = Mtl.reader targetHeader >>= \header ->
    maybe (Mtl.throwError (err header)) return $ lookup header (requestHeaders req)

-- * generic utilities

justWhen :: (a -> Bool) -> a -> Maybe a
justWhen p a = if p a then Just a else Nothing

justUnless :: (a -> Bool) -> a -> Maybe a
justUnless p a = if p a then Nothing else Just a

allRead :: (Applicative m, Foldable t) => t (a -> m b) -> a -> m ()
allRead l v = for_ l  ($ v)
