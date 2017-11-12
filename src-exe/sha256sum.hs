{-# LANGUAGE RecordWildCards #-}

module Main where

import           Control.Monad
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8  as B
import qualified Data.ByteString.Lazy   as BL
import           System.Console.GetOpt
import           System.Environment
import           System.Exit
import           System.IO

import qualified Crypto.Hash.SHA256     as H


data Options = Options
    { optBinary :: Bool
    , optHelp   :: Bool
    , optTag    :: Bool
    } deriving Show

defOptions :: Options
defOptions = Options
    { optBinary = True
    , optHelp = False
    , optTag  = False
    }

options :: [OptDescr (Options -> Options)]
options = [ Option ['b'] ["binary"]
            (NoArg (\o -> o { optBinary = True}))
            "read in binary mode (default)"
          , Option ['t'] ["text"]
            (NoArg (\o -> o { optBinary = False}))
            "read in text mode (ignored)"
          , Option [] ["help"]
            (NoArg (\o -> o { optHelp = True}))
            "display help and exit"
          , Option [] ["tag"]
            (NoArg (\o -> o { optTag = True}))
            "create a BSD-style checksum"
          ]

main :: IO ()
main = do
  argv <- getArgs

  let Options{..} = foldl (flip id) defOptions optset
      (optset,args0,cliErr) = getOpt Permute options argv
      args | null args0 = ["-"]
           | otherwise  = args0

  unless (null cliErr) $ do
    hPutStrLn stderr ("sha256sum: " ++ head cliErr ++ "Try 'sha256sum --help' for more information.")
    exitFailure

  when optHelp $ do
    putStrLn (usageInfo "Usage: sha256sum [OPTION]... [FILE]...\nPrint or check SHA-256 hashes\n" options)
    exitSuccess

  forM_ args $ \fn -> do
    h <- (B16.encode . H.hashlazy) `fmap` bReadFile fn

    case optTag of
      False -> do
        B.hPutStr stdout h
        hPutStrLn stdout (' ':' ':fn)
      True -> do
        hPutStrLn stdout $ concat [ "SHA256 (", fn, ") = ", B.unpack h ]

  return ()

bReadFile :: FilePath -> IO BL.ByteString
bReadFile "-" = do
  clsd <- hIsClosed stdin
  if clsd then return BL.empty else BL.getContents
bReadFile fn  = BL.readFile fn
