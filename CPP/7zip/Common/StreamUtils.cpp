// StreamUtils.cpp

#include "StdAfx.h"

#include "StreamUtils.h"

static const UInt32 kBlockSize = ((UInt32)1 << 31);

HRESULT ReadStream(ISequentialInStream *stream, void *data, size_t *processedSize) throw()
{
  size_t size = *processedSize;
  *processedSize = 0;
  while (size != 0)
  {
    UInt32 curSize = (size < kBlockSize) ? (UInt32)size : kBlockSize;
    UInt32 processedSizeLoc;
    HRESULT res = stream->Read(data, curSize, &processedSizeLoc);
    *processedSize += processedSizeLoc;
    data = (void *)((Byte *)data + processedSizeLoc);
    size -= processedSizeLoc;
    RINOK(res);
    if (processedSizeLoc == 0)
      return S_OK;
  }
  return S_OK;
}

HRESULT ReadStream_FALSE(ISequentialInStream *stream, void *data, size_t size) throw()
{
  size_t processedSize = size;
  RINOK(ReadStream(stream, data, &processedSize));
  return (size == processedSize) ? S_OK : S_FALSE;
}

HRESULT ReadStream_FAIL(ISequentialInStream *stream, void *data, size_t size) throw()
{
  size_t processedSize = size;
  RINOK(ReadStream(stream, data, &processedSize));
  return (size == processedSize) ? S_OK : E_FAIL;
}

HRESULT WriteStream(ISequentialOutStream *stream, const void *data, size_t size) throw()
{
  while (size != 0)
  {
    UInt32 curSize = (size < kBlockSize) ? (UInt32)size : kBlockSize;
    UInt32 processedSizeLoc;
    HRESULT res = stream->Write(data, curSize, &processedSizeLoc);
    data = (const void *)((const Byte *)data + processedSizeLoc);
    size -= processedSizeLoc;
    RINOK(res);
    if (processedSizeLoc == 0)
      return E_FAIL;
  }
  return S_OK;
}

HRESULT ReadStreamGreedy(ISequentialInStream *stream, void *data, size_t *processedSize) throw()
{
  size_t size = *processedSize;
  *processedSize = 0;
  do
  {
    UInt32 curSize = (size < kBlockSize) ? (UInt32)size : kBlockSize;
    UInt32 processedSizeLoc;
    HRESULT res = stream->Read(data, curSize, &processedSizeLoc);
    *processedSize += processedSizeLoc;
    data = (void *)((Byte *)data + processedSizeLoc);
    size -= processedSizeLoc;
    RINOK(res);
    if (processedSizeLoc == 0)
      return S_OK;
  }
  while (size > MAX_REM_PART_SIZE);
  return S_OK;
}

UInt32 GetPaddingSize(Byte *dataEnd)
{
  // check padding present and estimate its length:
  if (*(--dataEnd) <= 16) { // AES_BLOCK_SIZE
    Byte padChar = *dataEnd--;
    Byte padSize = padChar-1;
    while (padSize && *dataEnd == padChar) {
      padSize--; dataEnd--;
    }
    if (!padSize) {// valid PKCS#7 padding
      return padChar; // size of padding = number of padding bytes
    }
  }
  return 0;
}

HRESULT WriteStreamRemPart(ISequentialOutStream *stream, void *data, size_t size, size_t *remSize) throw()
{
  HRESULT res = S_OK;
  const void *cur = data; 
  do
  {
    UInt32 curSize = (size < kBlockSize) ? (UInt32)size : kBlockSize;
    UInt32 processedSizeLoc;
    res = stream->Write(cur, curSize, &processedSizeLoc);
    size -= processedSizeLoc;
    if (res != S_OK) {
      goto done;
    }
    cur = (const void *)((const Byte *)cur + processedSizeLoc);
    if (processedSizeLoc == 0) {
      if (stream->Finalize && size > 0)
        return E_UNEXPECTED;
      break;
    }
  }
  while (size > (!stream->Finalize ? MAX_REM_PART_SIZE : 0));
  // move remaining part to the start of buffer (will be processed later):
  if (size)
    memmove(data, cur, size);
done:
  *remSize = size;
  return S_OK;
}
