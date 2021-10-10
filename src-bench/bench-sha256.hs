{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE PackageImports #-}

import           Criterion.Main

import qualified "cryptohash-sha256"      Crypto.Hash.SHA256        as IUT
import qualified Data.Digest.Pure.SHA                               as REF

#ifdef VERSION_cryptohash_sha256_pure
import qualified "cryptohash-sha256-pure" Crypto.Hash.SHA256.Legacy as Pure
#endif

import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L

benchSize'IUT :: Int -> Benchmark
benchSize'IUT sz = bs `seq` bench msg (whnf IUT.hash bs)
  where
    bs = B.replicate sz 0
    msg = "bs-" ++ show sz

#ifdef VERSION_cryptohash_sha256_pure
benchSize'Pure :: Int -> Benchmark
benchSize'Pure sz = bs `seq` bench msg (whnf Pure.hash bs)
  where
    bs = B.replicate sz 0
    msg = "bs-" ++ show sz
#endif

benchSize'REF :: Int -> Benchmark
benchSize'REF sz = bs `seq` bench msg (whnf REF.sha256 bs)
  where
    bs = L.fromStrict (B.replicate sz 0)
    msg = "bs-" ++ show sz


main :: IO ()
main = do
    let !lbs64x256  = L.fromChunks $ replicate 4  (B.replicate 64 0)
        !lbs64x4096 = L.fromChunks $ replicate 64 (B.replicate 64 0)
    defaultMain
        [ bgroup "cryptohash-sha256"
          [ benchSize'IUT 0
          , benchSize'IUT 32
          , benchSize'IUT 64
          , benchSize'IUT 128
          , benchSize'IUT 1024
          , benchSize'IUT 4096
          , benchSize'IUT (32*1024)
          , benchSize'IUT (128*1024)
          , benchSize'IUT (1024*1024)
          , benchSize'IUT (2*1024*1024)
          , benchSize'IUT (4*1024*1024)

          , L.length lbs64x256  `seq` bench "lbs64x256"  (whnf IUT.hashlazy lbs64x256)
          , L.length lbs64x4096 `seq` bench "lbs64x4096" (whnf IUT.hashlazy lbs64x4096)
          ]

#ifdef VERSION_cryptohash_sha256_pure
        , bgroup "cryptohash-sha256-pure"
          [ benchSize'Pure 0
          , benchSize'Pure 32
          , benchSize'Pure 64
          , benchSize'Pure 128
          , benchSize'Pure 1024
          , benchSize'Pure 4096
          , benchSize'Pure (32*1024)
          , benchSize'Pure (128*1024)
          , benchSize'Pure (1024*1024)
          , benchSize'Pure (2*1024*1024)
          , benchSize'Pure (4*1024*1024)

          , L.length lbs64x256  `seq` bench "lbs64x256"  (whnf Pure.hashlazy lbs64x256)
          , L.length lbs64x4096 `seq` bench "lbs64x4096" (whnf Pure.hashlazy lbs64x4096)
          ]
#endif
        , bgroup "SHA"
          [ benchSize'REF 0
          , benchSize'REF 32
          , benchSize'REF 64
          , benchSize'REF 128
          , benchSize'REF 1024
          , benchSize'REF 4096
          , benchSize'REF (32*1024)
          , benchSize'REF (128*1024)
          , benchSize'REF (1024*1024)
          , benchSize'REF (2*1024*1024)
          , benchSize'REF (4*1024*1024)
          ]
        ]
