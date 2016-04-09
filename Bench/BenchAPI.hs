{-# LANGUAGE BangPatterns #-}
import Criterion.Main
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Hash.SHA256 as SHA256

sha256F = ( "SHA256"
        , SHA256.hash
        , SHA256.finalize . SHA256.update SHA256.init
        )

main = do
    let !bs32     = B.replicate 32 0
        !bs256    = B.replicate 256 0
        !bs4096   = B.replicate 4096 0
        !bs1M     = B.replicate (1*1024*1024) 0
    let !lbs64x256 = (map (const (B.replicate 64 0)) [0..3])
        !lbs64x4096 = (map (const (B.replicate 64 0)) [0..63])

    let (fname, fHash, fIncr) = sha256F
    let benchName ty z = fname ++ "." ++ ty -- ++ " " ++ show z
    defaultMain
        [ bgroup "hash-0b"
            [ bench (benchName "hash" 0) $ whnf fHash B.empty
            , bench (benchName "incr" 0) $ whnf fIncr B.empty
            ]
        , bgroup "hash-32b"
            [ bench (benchName "hash" 32) $ whnf fHash bs32
            , bench (benchName "incr" 32) $ whnf fIncr bs32
            ]
        , bgroup "hash-256b"
            [ bench (benchName "hash" 256) $ whnf fHash bs256
            , bench (benchName "incr" 256) $ whnf fIncr bs256
            ]
        , bgroup "hash-4Kb"
            [ bench (benchName "hash" 4096) $ whnf fHash bs4096
            , bench (benchName "incr" 4096) $ whnf fIncr bs4096
            ]
        ]
