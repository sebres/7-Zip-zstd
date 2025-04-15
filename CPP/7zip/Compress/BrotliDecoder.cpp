// (C) 2017 Tino Reichardt

#include "StdAfx.h"
#include "BrotliDecoder.h"

int BrotliRead(void *arg, BROTLIMT_Buffer * in)
{
  struct BrotliStream *x = (struct BrotliStream*)arg;
  size_t size = in->size;

  HRESULT res = ReadStreamGreedy(x->inStream, in->buf, &size);

  /* catch errors */
  switch (res) {
  case E_ABORT:
    return -2;
  case E_OUTOFMEMORY:
    return -3;
  }

  /* some other error -> read_fail */
  if (res != S_OK)
    return -1;

  in->size = size;
  *x->processedIn += size;

  return 0;
}

int BrotliWrite(void *arg, BROTLIMT_Buffer * out)
{
  struct BrotliStream *x = (struct BrotliStream*)arg;
  UInt32 todo = (UInt32)out->size;
  UInt32 done = 0;
  if (out->final)
    x->outStream->Finalize = true;
  HRESULT res;

  do
  {
    UInt32 block = 0;
    res = x->outStream->Write((char*)out->buf + done, todo, &block);

    done += block;

    if (res != S_OK) {
      /* catch errors */
      switch (res) {
      case E_ABORT:
        res = -2;
        break;
      case E_OUTOFMEMORY:
        res = -3;
        break;
      case k_My_HRESULT_WritingWasCut: // ???
        res = S_OK;
        break;
      }
      todo = 0; // don't move mem below (processing stopped)
      break;
    }

    if (block == 0 && todo != 0) {
      res = -1;
      break;
    }
    todo -= block;
  } 
  while (todo > out->max_rem_part);
  
  if (todo) {
    memmove(out->buf, (Byte*)out->buf + done, todo);
  }
  if (out->max_rem_part)
    out->size = todo;

  *x->processedOut += done;
  /* we need no lock here, cause only one thread can write... */
  if (x->progress)
    x->progress->SetRatioInfo(x->processedIn, x->processedOut);

  return res;
}

namespace NCompress {
namespace NBROTLI {

CDecoder::CDecoder():
  _processedIn(0),
  _processedOut(0),
  _inputSize(0),
  _numThreads(NWindows::NSystem::GetNumberOfProcessors())
{
  _props.clear();
}

CDecoder::~CDecoder()
{
}

Z7_COM7F_IMF(CDecoder::SetDecoderProperties2(const Byte * prop, UInt32 size))
{
  DProps *pProps = (DProps *)prop;

  if (size != sizeof(DProps))
    return E_NOTIMPL;

  memcpy(&_props, pProps, sizeof (DProps));

  return S_OK;
}

Z7_COM7F_IMF(CDecoder::SetNumberOfThreads(UInt32 numThreads))
{
  const UInt32 kNumThreadsMax = BROTLIMT_THREAD_MAX;
  // if single-threaded, retain artificial number set in BrotliHandler (always prefer .br format):
  if ((int)numThreads < 1) {
    numThreads = 0;
  }
  else
  if (numThreads > kNumThreadsMax) numThreads = kNumThreadsMax;
  _numThreads = numThreads;
  return S_OK;
}

HRESULT CDecoder::SetOutStreamSizeResume(const UInt64 * /*outSize*/)
{
  _processedOut = 0;
  return S_OK;
}

Z7_COM7F_IMF(CDecoder::SetOutStreamSize(const UInt64 * outSize))
{
  _processedIn = 0;
  RINOK(SetOutStreamSizeResume(outSize));
  return S_OK;
}

HRESULT CDecoder::CodeSpec(ISequentialInStream * inStream,
  ISequentialOutStream * outStream, ICompressProgressInfo * progress)
{
  BROTLIMT_RdWr_t rdwr;
  size_t result;
  HRESULT res = S_OK;

  struct BrotliStream Rd;
  Rd.inStream = inStream;
  Rd.processedIn = &_processedIn;

  struct BrotliStream Wr;
  Wr.progress = progress;
  Wr.outStream = outStream;
  Wr.processedIn = &_processedIn;
  Wr.processedOut = &_processedOut;

  /* 1) setup read/write functions */
  rdwr.fn_read = ::BrotliRead;
  rdwr.fn_write = ::BrotliWrite;
  rdwr.arg_read = (void *)&Rd;
  rdwr.arg_write = (void *)&Wr;

  /* 2) create decompression context */
  BROTLIMT_DCtx *ctx = BROTLIMT_createDCtx(_numThreads, _inputSize);
  if (!ctx)
      return S_FALSE;

  /* 3) decompress */
  result = BROTLIMT_decompressDCtx(ctx, &rdwr);
  if (result == k_My_HRESULT_WritingDone)
      res = (HRESULT)result;
  else if (BROTLIMT_isError(result)) {
    res = E_FAIL;
    if (result == (size_t)-BROTLIMT_error_canceled)
      res = E_ABORT;
  }

  /* 4) free resources */
  BROTLIMT_freeDCtx(ctx);
  return res;
}

Z7_COM7F_IMF(CDecoder::Code(ISequentialInStream * inStream, ISequentialOutStream * outStream,
  const UInt64 * /*inSize */, const UInt64 *outSize, ICompressProgressInfo * progress))
{
  SetOutStreamSize(outSize);
  return CodeSpec(inStream, outStream, progress);
}

#ifndef Z7_NO_READ_FROM_CODER
Z7_COM7F_IMF(CDecoder::SetInStream(ISequentialInStream * inStream))
{
  _inStream = inStream;
  return S_OK;
}

Z7_COM7F_IMF(CDecoder::ReleaseInStream())
{
  _inStream.Release();
  return S_OK;
}
#endif

HRESULT CDecoder::CodeResume(ISequentialOutStream * outStream, const UInt64 * outSize, ICompressProgressInfo * progress)
{
  RINOK(SetOutStreamSizeResume(outSize));
  return CodeSpec(_inStream, outStream, progress);
}

}}
