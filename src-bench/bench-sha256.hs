{-# LANGUAGE BangPatterns #-}

import           Criterion.Main
import qualified Crypto.Hash.SHA256   as SHA256
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L

benchSize :: Int -> Benchmark
benchSize sz = bs `seq` bench msg (whnf SHA256.hash bs)
  where
    bs = B.replicate sz 0
    msg = "bs-" ++ show sz

main :: IO ()
main = do
    let !lbs64x256  = L.fromChunks $ replicate 4  (B.replicate 64 0)
        !lbs64x4096 = L.fromChunks $ replicate 64 (B.replicate 64 0)
    defaultMain
        [ bgroup "cryptohash-sha256"
          [ benchSize 0
          , benchSize 8
          , benchSize 32
          , benchSize 64
          , benchSize 128
          , benchSize 256
          , benchSize 1024
          , benchSize 4096
          , benchSize (128*1024)
          , benchSize (1024*1024)
          , benchSize (2*1024*1024)
          , benchSize (4*1024*1024)

          , L.length lbs64x256  `seq` bench "lbs64x256"  (whnf SHA256.hashlazy lbs64x256)
          , L.length lbs64x4096 `seq` bench "lbs64x4096" (whnf SHA256.hashlazy lbs64x4096)
          ]
        ]
