{-# LANGUAGE BangPatterns #-}
import Criterion.Main
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Hash.SHA256 as SHA256

hashmany (i,u,f) = f . foldl u i

allHashs =
    [ ("SHA2-256",SHA256.hash, hashmany (SHA256.init,SHA256.update,SHA256.finalize))
    ]

benchHash :: a -> (a -> B.ByteString) -> Benchmarkable
benchHash bs f = whnf f bs

withHashesFilter out f = map f $ filter (\(n,_,_) -> not (n `elem` out)) allHashs
withHashes f = map f allHashs

main = do
    let !bs32     = B.replicate 32 0
        !bs256    = B.replicate 256 0
        !bs4096   = B.replicate 4096 0
        !bs1M     = B.replicate (1*1024*1024) 0
    let !lbs64x256 = (map (const (B.replicate 64 0)) [0..3])
        !lbs64x4096 = (map (const (B.replicate 64 0)) [0..63])
    defaultMain
        [ bgroup "hash-32b" (withHashes (\(name, f,_) -> bench name $ benchHash bs32 f))
        , bgroup "hash-256b" (withHashes (\(name, f,_) -> bench name $ benchHash bs256 f))
        , bgroup "hash-4Kb" (withHashes (\(name, f,_) -> bench name $ benchHash bs4096 f))
        , bgroup "hash-1Mb" (withHashesFilter ["MD2"] (\(name, f,_) -> bench name $ benchHash bs1M f))
        , bgroup "iuf-64x256" (withHashes (\(name, _,f) -> bench name $ benchHash lbs64x256 f))
        , bgroup "iuf-64x4096" (withHashes (\(name, _,f) -> bench name $ benchHash lbs64x4096 f))
        ]
