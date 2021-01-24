{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Trustworthy  #-}

-- |
-- Module      : Crypto.Hash.SHA256
-- License     : BSD-3
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
--
-- A module containing <https://en.wikipedia.org/wiki/SHA-2 SHA-256> bindings
--
module Crypto.Hash.SHA256
    (

    -- * Incremental API
    --
    -- | This API is based on 4 different functions, similar to the
    -- lowlevel operations of a typical hash:
    --
    --  - 'init': create a new hash context
    --  - 'update': update non-destructively a new hash context with a strict bytestring
    --  - 'updates': same as update, except that it takes a list of strict bytestrings
    --  - 'finalize': finalize the context and returns a digest bytestring.
    --
    -- all those operations are completely pure, and instead of
    -- changing the context as usual in others language, it
    -- re-allocates a new context each time.
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA256 as SHA256
    -- >
    -- > main = print digest
    -- >   where
    -- >     digest = SHA256.finalize ctx
    -- >     ctx    = foldl SHA256.update ctx0 (map Data.ByteString.pack [ [1,2,3], [4,5,6] ])
    -- >     ctx0   = SHA256.init

      Ctx(..)
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString
    , finalizeAndLength -- :: Ctx -> (ByteString,Word64)
    , start     -- :: ByteString -> Ct
    , startlazy -- :: L.ByteString -> Ctx

    -- * Single Pass API
    --
    -- | This API use the incremental API under the hood to provide
    -- the common all-in-one operations to create digests out of a
    -- 'ByteString' and lazy 'L.ByteString'.
    --
    --  - 'hash': create a digest ('init' + 'update' + 'finalize') from a strict 'ByteString'
    --  - 'hashlazy': create a digest ('init' + 'update' + 'finalize') from a lazy 'L.ByteString'
    --  - 'hashlazyAndLength': create a digest ('init' + 'update' + 'finalizeAndLength') from a lazy 'L.ByteString'
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA256 as SHA256
    -- >
    -- > main = print $ SHA256.hash (Data.ByteString.pack [0..255])
    --
    -- __NOTE__: The returned digest is a binary 'ByteString'. For
    -- converting to a base16/hex encoded digest the
    -- <https://hackage.haskell.org/package/base16-bytestring base16-bytestring>
    -- package is recommended.

    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: L.ByteString -> ByteString
    , hashlazyAndLength -- :: L.ByteString -> (ByteString,Int64)

    -- ** HMAC-SHA-256
    --
    -- | <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
    -- <https://en.wikipedia.org/wiki/HMAC HMAC>-SHA-256 digests

    , hmac     -- :: ByteString -> ByteString -> ByteString
    , hmaclazy -- :: ByteString -> L.ByteString -> ByteString
    , hmaclazyAndLength -- :: ByteString -> L.ByteString -> (ByteString,Word64)

    -- ** HKDF-SHA-256
    --
    -- | <https://tools.ietf.org/html/rfc5869 RFC5869>-compatible
    -- <https://en.wikipedia.org/wiki/HKDF HKDF>-SHA-256 key derivation function

    , hkdf
    ) where

import Prelude ()
import Crypto.Hash.SHA256.Legacy
