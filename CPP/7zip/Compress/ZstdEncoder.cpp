// (C) 2016 - 2020 Tino Reichardt

#include "StdAfx.h"
#include "ZstdEncoder.h"
#include "ZstdDecoder.h"

#ifndef Z7_EXTRACT_ONLY
namespace NCompress {
namespace NZSTD {

CEncoder::CEncoder():
  _ctx(NULL),
  _srcBuf(NULL),
  _dstBuf(NULL),
  _srcBufSize(ZSTD_CStreamInSize()),
  _dstBufSize(ZSTD_CStreamOutSize()),
  _processedIn(0),
  _processedOut(0),
  _numThreads(NWindows::NSystem::GetNumberOfProcessors()),
  _Long(-1),
  _Level(ZSTD_CLEVEL_DEFAULT),
  _Strategy(-1),
  _WindowLog(-1),
  _HashLog(-1),
  _ChainLog(-1),
  _SearchLog(-1),
  _MinMatch(-1),
  _TargetLen(-1),
  _OverlapLog(-1),
  _LdmHashLog(-1),
  _LdmMinMatch(-1),
  _LdmBucketSizeLog(-1),
  _LdmHashRateLog(-1),
  dictIDFlag(-1),
  checksumFlag(-1),
  unpackSize(0)
{
  _props.clear();
}

CEncoder::~CEncoder()
{
  if (_ctx) {
    ZSTD_freeCCtx(_ctx);
    MyFree(_srcBuf);
    ISzAlloc_Free(&g_AlignedAlloc, _dstBuf);
  }
}

Z7_COM7F_IMF(CEncoder::SetCoderProperties(const PROPID * propIDs, const PROPVARIANT * coderProps, UInt32 numProps))
{
  _props.clear();

  for (UInt32 i = 0; i < numProps; i++)
  {
    const PROPVARIANT & prop = coderProps[i];
    PROPID propID = propIDs[i];
    UInt32 v = (UInt32)prop.ulVal;
    switch (propID)
    {
    case NCoderPropID::kNumThreads:
      {
        SetNumberOfThreads(v);
        break;
      }
    case NCoderPropID::kStrategy:
      {
        if (v < 1) v = 1;
        if (v > 8) v = 8;
        _Strategy = v;
        break;
      }
    case NCoderPropID::kLevel:
      {
        _Level = v;
        if (v < 1) {
          _Level = 1;
        } else if ((Int32)v > ZSTD_maxCLevel()) {
          _Level = ZSTD_maxCLevel();
        }

        /**
         * zstd default levels: _Level => 1..ZSTD_maxCLevel()
         */
        _props._level = static_cast < Byte > (_Level);
        break;
      }
    case NCoderPropID::kFast:
      {
        /* like --fast in zstd cli program */
        UInt32 _Fast = v;

        if (v < 1) {
          _Fast = 1;
        } else if (v > 64) {
          _Fast = 64;
        }

        /**
         * zstd fast levels:
         * _Fast  => 1..ZSTD_minCLevel()  (_Level => _Fast + 32)
         */
        _props._level = static_cast < Byte > (_Fast + 32);

        /* negative levels are the fast ones */
        _Level = _Fast * -1;
        break;
      }
    case NCoderPropID::kLong:
      {
        /* like --long in zstd cli program */
        _Long = 1;
        if (v == 0) {
          // m0=zstd:long:tlen=x -> long=default
          _WindowLog = 27;
        } else if (v < ZSTD_WINDOWLOG_MIN) {
          // m0=zstd:long=9 -> long=10
          _WindowLog = ZSTD_WINDOWLOG_MIN;
        } else if (v > ZSTD_WINDOWLOG_MAX) {
          // m0=zstd:long=33 -> long=max
          _WindowLog = ZSTD_WINDOWLOG_MAX;
        } else {
          // m0=zstd:long=15 -> long=value
          _WindowLog = v;
        }
        break;
      }
    case NCoderPropID::kWindowLog:
      {
        if (v < ZSTD_WINDOWLOG_MIN) v = ZSTD_WINDOWLOG_MIN;
        if (v > ZSTD_WINDOWLOG_MAX) v = ZSTD_WINDOWLOG_MAX;
        _WindowLog = v;
        break;
      }
    case NCoderPropID::kHashLog:
      {
        if (v < ZSTD_HASHLOG_MIN) v = ZSTD_HASHLOG_MIN;
        if (v > ZSTD_HASHLOG_MAX) v = ZSTD_HASHLOG_MAX;
        _HashLog = v;
        break;
      }
    case NCoderPropID::kChainLog:
      {
        if (v < ZSTD_CHAINLOG_MIN) v = ZSTD_CHAINLOG_MIN;
        if (v > ZSTD_CHAINLOG_MAX) v = ZSTD_CHAINLOG_MAX;
        _ChainLog = v;
        break;
      }
    case NCoderPropID::kSearchLog:
      {
        if (v < ZSTD_SEARCHLOG_MIN) v = ZSTD_SEARCHLOG_MIN;
        if (v > ZSTD_SEARCHLOG_MAX) v = ZSTD_SEARCHLOG_MAX;
        _SearchLog = v;
        break;
      }
    case NCoderPropID::kMinMatch:
      {
        if (v < ZSTD_MINMATCH_MIN) v = ZSTD_MINMATCH_MIN;
        if (v > ZSTD_MINMATCH_MAX) v = ZSTD_MINMATCH_MAX;
        _MinMatch = v;
        break;
      }
    case NCoderPropID::kTargetLen:
      {
      #if ZSTD_TARGETLENGTH_MIN > 0
        if (v < ZSTD_TARGETLENGTH_MIN) v = ZSTD_TARGETLENGTH_MIN;
      #endif
        if (v > ZSTD_TARGETLENGTH_MAX) v = ZSTD_TARGETLENGTH_MAX;
        _TargetLen = 0;
        break;
      }
    case NCoderPropID::kOverlapLog:
      {
        // if (v < 0) v = 0; /* no overlap */
        if (v > 9) v = 9; /* full size */
        _OverlapLog = v;
        break;
      }
    case NCoderPropID::kLdmHashLog:
      {
        if (v < ZSTD_HASHLOG_MIN) v = ZSTD_HASHLOG_MIN;
        if (v > ZSTD_HASHLOG_MAX) v = ZSTD_HASHLOG_MAX;
        _LdmHashLog = v;
        break;
      }
    case NCoderPropID::kLdmSearchLength:
      {
        if (v < ZSTD_LDM_MINMATCH_MIN) v = ZSTD_LDM_MINMATCH_MIN;
        if (v > ZSTD_LDM_MINMATCH_MAX) v = ZSTD_LDM_MINMATCH_MAX;
        _LdmMinMatch = v;
        break;
      }
    case NCoderPropID::kLdmBucketSizeLog:
      {
        if (v < 1) v = 1;
        if (v > ZSTD_LDM_BUCKETSIZELOG_MAX) v = ZSTD_LDM_BUCKETSIZELOG_MAX;
        _LdmBucketSizeLog = v;
        break;
      }
    case NCoderPropID::kLdmHashRateLog:
      {
        // if (v < 0) v = 0; /* 0 => automatic mode */
        if (v > (ZSTD_WINDOWLOG_MAX - ZSTD_HASHLOG_MIN)) v = (ZSTD_WINDOWLOG_MAX - ZSTD_HASHLOG_MIN);
        _LdmHashRateLog = v;
        break;
      }
    default:
      {
        break;
      }
    }
  }

  return S_OK;
}

Z7_COM7F_IMF(CEncoder::WriteCoderProperties(ISequentialOutStream * outStream))
{
  return WriteStream(outStream, &_props, sizeof (_props));
}

Z7_COM7F_IMF(CEncoder::Code(ISequentialInStream *inStream,
  ISequentialOutStream *outStream, const UInt64 * /*inSize*/ ,
  const UInt64 * /*outSize */, ICompressProgressInfo *progress))
{
  ZSTD_EndDirective ZSTD_todo = ZSTD_e_continue;
  ZSTD_outBuffer outBuff;
  ZSTD_inBuffer inBuff;
  size_t err, srcSize;

  _processedIn = 0;
  _processedOut = 0;

  if (!_ctx) {
    _ctx = ZSTD_createCCtx();
    if (!_ctx)
      return E_OUTOFMEMORY;

    _srcBuf = MyAlloc(_srcBufSize);
    if (!_srcBuf)
      return E_OUTOFMEMORY;

    // aligned because of possible HW AES encryption, +16 = +AES_BLOCK_SIZE for PKCS#7 padding 16 * \x16
    _dstBuf = ISzAlloc_Alloc(&g_AlignedAlloc, _dstBufSize+16);
    if (!_dstBuf)
      return E_OUTOFMEMORY;

    /* setup level */
    err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_compressionLevel, (UInt32)_Level);
    if (ZSTD_isError(err)) return E_INVALIDARG;

    /* setup thread count */
    err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_nbWorkers, _numThreads);
    if (ZSTD_isError(err)) return E_INVALIDARG;

    /* set the content size flag */
    err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_contentSizeFlag, 1);
    if (ZSTD_isError(err)) return E_INVALIDARG;

    if (dictIDFlag != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_dictIDFlag, dictIDFlag);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }
    if (checksumFlag != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_checksumFlag, checksumFlag);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (unpackSize && unpackSize != (UInt64)(Int64)-1) { // size is known
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_srcSizeHint, (int)(unpackSize <= INT_MAX ? unpackSize : INT_MAX));
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    /* enable ldm for large windowlog values */
    if (_WindowLog > 27 && _Long == 0)
      _Long = 1;

    /* set ldm */
    if (_Long != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_enableLongDistanceMatching, _Long);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_Strategy != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_strategy, _Strategy);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_WindowLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_windowLog, _WindowLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_HashLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_hashLog, _HashLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_ChainLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_chainLog, _ChainLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_SearchLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_searchLog, _SearchLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_MinMatch != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_minMatch, _MinMatch);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_TargetLen != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_targetLength, _TargetLen);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_OverlapLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_overlapLog, _OverlapLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_LdmHashLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_ldmHashLog, _LdmHashLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_LdmMinMatch != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_ldmMinMatch, _LdmMinMatch);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_LdmBucketSizeLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_ldmBucketSizeLog, _LdmBucketSizeLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    if (_LdmHashRateLog != -1) {
      err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_ldmHashRateLog, _LdmHashRateLog);
      if (ZSTD_isError(err)) return E_INVALIDARG;
    }

    //err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_literalCompressionMode, (int)ZSTD_ps_auto);
    //if (ZSTD_isError(err)) return E_INVALIDARG;

    //err = ZSTD_CCtx_setParameter(_ctx, ZSTD_c_enableDedicatedDictSearch, 1);
    //if (ZSTD_isError(err)) return E_INVALIDARG;
  }

  outBuff.dst = _dstBuf;
  outBuff.size = _dstBufSize; // buffer normally always larger than AES_BLOCK_SIZE, for possible padding of block if needed (if encryption in-place)
  outBuff.pos = 0;
  for (;;) {

    /* read input */
    srcSize = _srcBufSize;
    RINOK(ReadStream(inStream, _srcBuf, &srcSize))

    /* eof */
    inBuff.src = _srcBuf;
    inBuff.size = srcSize;
    inBuff.pos = 0;
    if (srcSize == 0) {
      inBuff.src = NULL;
      ZSTD_todo = ZSTD_e_end;
    }

    /* compress data */
    _processedIn += srcSize;

    for (;;) {

      err = ZSTD_compressStream2(_ctx, &outBuff, &inBuff, ZSTD_todo);
      if (ZSTD_isError(err)) {
        switch (ZSTD_getErrorCode(err)) {
          /* @Igor: would be nice, if we have an API to store the errmsg */
          case ZSTD_error_memory_allocation:
            return E_OUTOFMEMORY;
          case ZSTD_error_version_unsupported:
          case ZSTD_error_frameParameter_unsupported:
            return E_NOTIMPL;
          case ZSTD_error_frameParameter_windowTooLarge:
          case ZSTD_error_parameter_unsupported:
          case ZSTD_error_parameter_outOfBound:
            return E_INVALIDARG;
          default:
            return E_FAIL;
        }
      }

      /* write output */
      if (outBuff.pos) {
        size_t remPart;
        RINOK(WriteStreamRemPart(outStream, _dstBuf, outBuff.pos, &remPart));
        _processedOut += outBuff.pos;
        outBuff.pos = remPart;
      }

      if (progress)
        RINOK(progress->SetRatioInfo(&_processedIn, &_processedOut))

      /* done */
      if (ZSTD_todo == ZSTD_e_end && err == 0) {
        outStream->Finalize = true; // should write to the end
        size_t remPart;
        RINOK(WriteStreamRemPart(outStream, _dstBuf, outBuff.pos, &remPart));
        if (remPart)
          return E_UNEXPECTED; // remPart must be 0
        return S_OK;
      }

      /* need more input */
      if (inBuff.pos == inBuff.size && inBuff.src)
        break;
    }
  }
}

Z7_COM7F_IMF(CEncoder::SetNumberOfThreads(UInt32 numThreads))
{
  const UInt32 kNumThreadsMax = ZSTD_THREAD_MAX;
  if (numThreads < 1) numThreads = 1;
  if (numThreads > kNumThreadsMax) numThreads = kNumThreadsMax;
  _numThreads = numThreads;
  return S_OK;
}

}}
#endif
