-- |
-- Module      : Crypto.Hash.SHA256
-- License     : BSD-style
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
-- Portability : unknown
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
    --  - 'updates': same as update, except that it takes a list of strict bytestring
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

    -- * Single Pass API
    --
    -- | This API use the incremental API under the hood to provide
    -- the common all-in-one operations to create digests out of a
    -- 'ByteString' and lazy 'L.ByteString'.
    --
    --  - 'hash': create a digest ('init' + 'update' + 'finalize') from a strict 'ByteString'
    --  - 'hashlazy': create a digest ('init' + 'update' + 'finalize') from a lazy 'L.ByteString'
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA256 as SHA256
    -- >
    -- > main = print $ SHA256.hash (Data.ByteString.pack [0..255])

    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Storable
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, toForeignPtr)
import Data.Word
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | perform IO for hashes that do allocation and ffi.
-- unsafeDupablePerformIO is used when possible as the
-- computation is pure and the output is directly linked
-- to the input. we also do not modify anything after it has
-- been returned to the user.
unsafeDoIO :: IO a -> a
unsafeDoIO = unsafeDupablePerformIO

-- | SHA-256 Context
newtype Ctx = Ctx ByteString

{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 32

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 192

{-# RULES "digestSize" B.length (finalize init) = digestSize #-}
{-# RULES "hash" forall b. finalize (update init b) = hash b #-}
{-# RULES "hash.list1" forall b. finalize (updates init [b]) = hash b #-}
{-# RULES "hashmany" forall b. finalize (foldl update init b) = hashlazy (L.fromChunks b) #-}
{-# RULES "hashlazy" forall b. finalize (foldl update init $ L.toChunks b) = hashlazy b #-}

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

{-# INLINE memcopy64 #-}
memcopy64 :: Ptr Word64 -> Ptr Word64 -> IO ()
memcopy64 dst src = mapM_ peekAndPoke [0..(24-1)]
    where peekAndPoke i = peekElemOff src i >>= pokeElemOff dst i

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx ctxB) f = Ctx `fmap` createCtx
    where createCtx = create sizeCtx $ \dstPtr ->
                      withByteStringPtr ctxB $ \srcPtr -> do
                          memcopy64 (castPtr dstPtr) (castPtr srcPtr)
                          f (castPtr dstPtr)

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx ctxB) f =
    allocaBytes sizeCtx $ \dstPtr ->
    withByteStringPtr ctxB $ \srcPtr -> do
        memcopy64 (castPtr dstPtr) (castPtr srcPtr)
        f (castPtr dstPtr)

withCtxNew :: (Ptr Ctx -> IO ()) -> IO Ctx
withCtxNew f = Ctx `fmap` create sizeCtx (f . castPtr)

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = allocaBytes sizeCtx (f . castPtr)

foreign import ccall unsafe "sha256.h hs_cryptohash_sha256_init"
    c_sha256_init :: Ptr Ctx -> IO ()

foreign import ccall unsafe "sha256.h hs_cryptohash_sha256_update"
    c_sha256_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "sha256.h hs_cryptohash_sha256_finalize"
    c_sha256_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_sha256_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr = create digestSize (c_sha256_finalize ptr)

{-# NOINLINE init #-}
-- | init a context
init :: Ctx
init = unsafeDoIO $ withCtxNew $ c_sha256_init

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d

{-# NOINLINE updates #-}
-- | updates a context with multiples bytestring
updates :: Ctx -> [ByteString] -> Ctx
updates ctx d = unsafeDoIO $ withCtxCopy ctx $ \ptr -> mapM_ (updateInternalIO ptr) d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = unsafeDoIO $ withCtxThrow ctx finalizeInternalIO

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: ByteString -> ByteString
hash d = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_sha256_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafeDoIO $ withCtxNewThrow $ \ptr -> do
    c_sha256_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
