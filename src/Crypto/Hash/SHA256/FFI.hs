{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Unsafe  #-}

-- Ugly hack to workaround https://ghc.haskell.org/trac/ghc/ticket/14452
{-# OPTIONS_GHC -O0
                -fdo-lambda-eta-expansion
                -fcase-merge
                -fstrictness
                -fno-omit-interface-pragmas
                -fno-ignore-interface-pragmas #-}

{-# OPTIONS_GHC -optc-Wall -optc-O3 #-}

-- |
-- Module      : Crypto.Hash.SHA256.FFI
-- License     : BSD-3
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
--
module Crypto.Hash.SHA256.FFI where

import           Data.ByteString (ByteString)
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

-- | SHA-256 Context
--
-- The context data is exactly 104 bytes long, however
-- the data in the context is stored in host-endianness.
--
-- The context data is made up of
--
--  * a 'Word64' representing the number of bytes already feed to hash algorithm so far,
--
--  * a 64-element 'Word8' buffer holding partial input-chunks, and finally
--
--  * a 8-element 'Word32' array holding the current work-in-progress digest-value.
--
-- Consequently, a SHA-256 digest as produced by 'hash', 'hashlazy', or 'finalize' is 32 bytes long.
newtype Ctx = Ctx ByteString
  deriving (Eq)

foreign import capi unsafe "hs_sha256.h hs_cryptohash_sha256_init"
    c_sha256_init :: Ptr Ctx -> IO ()

foreign import capi unsafe "hs_sha256.h hs_cryptohash_sha256_update"
    c_sha256_update_unsafe :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()

foreign import capi safe "hs_sha256.h hs_cryptohash_sha256_update"
    c_sha256_update_safe :: Ptr Ctx -> Ptr Word8 -> CSize -> IO ()

foreign import capi unsafe "hs_sha256.h hs_cryptohash_sha256_finalize"
    c_sha256_finalize_len :: Ptr Ctx -> Ptr Word8 -> IO Word64

foreign import capi unsafe "hs_sha256.h hs_cryptohash_sha256_finalize"
    c_sha256_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

foreign import capi unsafe "hs_sha256.h hs_cryptohash_sha256_hash"
    c_sha256_hash_unsafe :: Ptr Word8 -> CSize -> Ptr Word8 -> IO ()

foreign import capi safe "hs_sha256.h hs_cryptohash_sha256_hash"
    c_sha256_hash_safe :: Ptr Word8 -> CSize -> Ptr Word8 -> IO ()
