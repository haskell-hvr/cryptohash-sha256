{-# LANGUAGE CPP          #-}
{-# LANGUAGE Trustworthy  #-}

-- |
-- Module      : Compat
-- License     : BSD-3
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
--
-- Compat layer to reduce code exposure to CPP to a bare minimum
--
module Compat (constructBS) where

import Foreign.ForeignPtr (ForeignPtr)
import Data.Word (Word8)
import Data.ByteString.Internal (ByteString (..))

-- | Directly construct a 'ByteString', unsafely
constructBS :: ForeignPtr Word8 -> Int -> ByteString
#if MIN_VERSION_bytestring(0,11,0)
constructBS = BS
#else
constructBS = \fp -> PS fp 0
#endif
