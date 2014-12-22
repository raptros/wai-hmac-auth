module Main where

import Test.Hspec
import Network.Wai 
import Network.Wai.Auth.HMAC

main :: IO ()
main = hspec $ do
    describe "getTimestampHeader" $ do
        it "gets the header if present" $ do
            pending
            
