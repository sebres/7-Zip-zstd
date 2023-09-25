// StreamUtils.h

#ifndef __STREAM_UTILS_H
#define __STREAM_UTILS_H

#include "../IStream.h"

HRESULT ReadStream(ISequentialInStream *stream, void *data, size_t *size) throw();
HRESULT ReadStream_FALSE(ISequentialInStream *stream, void *data, size_t size) throw();
HRESULT ReadStream_FAIL(ISequentialInStream *stream, void *data, size_t size) throw();
HRESULT WriteStream(ISequentialOutStream *stream, const void *data, size_t size) throw();

UInt32 GetPaddingSize(Byte* dataEnd);

// size of max remaining part after write (must be larger than AES_BLOCK_SIZE)
const unsigned MAX_REM_PART_SIZE = 1024;
HRESULT ReadStreamGreedy(ISequentialInStream *stream, void *data, size_t *processedSize) throw();
HRESULT WriteStreamRemPart(ISequentialOutStream *stream, void *data, size_t size, size_t *remSize) throw();

#endif
