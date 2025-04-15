// BrotliHandler.cpp

#include "StdAfx.h"

#include "../../../C/CpuArch.h"
#include "../../Common/ComTry.h"
#include "../../Common/Defs.h"

#include "../IPassword.h"

#include "../Common/ProgressUtils.h"
#include "../Common/RegisterArc.h"
#include "../Common/StreamUtils.h"

#include "../Compress/BrotliDecoder.h"
#include "../Compress/BrotliEncoder.h"
#include "../Compress/CopyCoder.h"

#ifndef _NO_CRYPTO
#include "../Crypto/AesStream.h"
#endif

#include "Common/DummyOutStream.h"
#include "Common/HandlerOut.h"

using namespace NWindows;

namespace NArchive {
namespace NBROTLI {

Z7_CLASS_IMP_CHandler_IInArchive_3(
  IArchiveOpenSeq,
  IOutArchive,
  ISetProperties
)
  CMyComPtr<IInStream> _stream;
  CMyComPtr<ISequentialInStream> _seqStream;
  #ifndef _NO_CRYPTO
  NCrypto::CAesInStream *_aesStream;
  HRESULT SetAesStreamForKey(IUnknown *callback, ISequentialInStream *stream);
  #endif

  bool _isArc;
  bool _dataAfterEnd;
  bool _needMoreInput;

  bool _packSize_Defined;
  bool _unpackSize_Defined;

  UInt64 _packSize;
  UInt64 _unpackSize;
  UInt64 _numStreams;
  UInt64 _numBlocks;

  CSingleMethodProps _props;

public:

  CHandler():
  #ifndef _NO_CRYPTO
  _aesStream(NULL)
  #endif
  { }

  ~CHandler() 
  {
    #ifndef _NO_CRYPTO
    if (_aesStream) {
      _aesStream = NULL;
    }
    #endif
  }
};

static const Byte kProps[] =
{
  kpidSize,
  kpidPackSize
};

static const Byte kArcProps[] =
{
  kpidNumStreams,
  kpidNumBlocks
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID /*propID*/, PROPVARIANT * /*value*/))
{
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *numItems))
{
  *numItems = 1;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetProperty(UInt32 /* index */, PROPID propID, PROPVARIANT *value))
{
  NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidPackSize: if (_packSize_Defined) prop = _packSize; break;
    case kpidSize: if (_unpackSize_Defined) prop = _unpackSize; break;
  }
  prop.Detach(value);
  return S_OK;
}

// brotli format has no signature
// brotli stream can't be veriefied unless errors by unpack
#if 0
API_FUNC_static_IsArc IsArc_Brotli(const Byte *p, size_t size)
{
  return k_IsArc_Res_YES;
}
}
#endif

Z7_COM7F_IMF(CHandler::Open(IInStream *stream, const UInt64 *, IArchiveOpenCallback *))
{
  COM_TRY_BEGIN
  Close();
  {
    _isArc = true;
    _stream = stream;
    _seqStream = stream;
  }
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::OpenSeq(ISequentialInStream *stream))
{
  Close();
  _isArc = true;
  _seqStream = stream;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::Close())
{
  _isArc = false;
  _dataAfterEnd = false;
  _needMoreInput = false;

  _packSize_Defined = false;
  _unpackSize_Defined = false;

  _packSize = 0;

  _seqStream.Release();
  _stream.Release();

  #ifndef _NO_CRYPTO
  if (_aesStream) {
    delete _aesStream;
    _aesStream = NULL;
  }
  #endif
  return S_OK;
}

#ifndef _NO_CRYPTO
HRESULT CHandler::SetAesStreamForKey(IUnknown * callback, ISequentialInStream *stream)
{
  HRESULT res = S_OK;
  CMyComPtr<ICryptoGetTextPassword> getTextPassword;
  callback->QueryInterface(IID_ICryptoGetTextPassword, (void **)&getTextPassword);
  if (getTextPassword)
  {
    UString_Wipe password;
    bool passwordIsDefined;
    RINOK(getTextPassword->CryptoGetPasswordIfAny(passwordIsDefined, password));
    if (passwordIsDefined) {
      _aesStream = new NCrypto::CAesInStream();
      res = _aesStream->Init(stream, password);
      password.Wipe_and_Empty();
    }
  }

  return res;
};
#endif

Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testMode, IArchiveExtractCallback *extractCallback))
{
  COM_TRY_BEGIN

  #ifndef _NO_CRYPTO
  HRESULT res;
  if (_aesStream == NULL) {
    if ((res = SetAesStreamForKey(extractCallback, _seqStream)) != S_OK) {
      return res;
    }
  }
  #endif

  if (numItems == 0)
    return S_OK;
  if (numItems != (UInt32)(Int32)-1 && (numItems != 1 || indices[0] != 0))
    return E_INVALIDARG;

  if (_packSize_Defined)
    extractCallback->SetTotal(_packSize);

  CMyComPtr<ISequentialOutStream> realOutStream;
  Int32 askMode = testMode ?
      NExtract::NAskMode::kTest :
      NExtract::NAskMode::kExtract;
  RINOK(extractCallback->GetStream(0, &realOutStream, askMode));
  if (!testMode && !realOutStream)
    return S_OK;

  extractCallback->PrepareOperation(askMode);

  Int32 opRes;

  {

  NCompress::NBROTLI::CDecoder *decoderSpec = new NCompress::NBROTLI::CDecoder;
  /*
   * Brotli stream doesn't contain info about threads and it is normally
   * single-threaded by default (.br files without header/mt-frames),
   * so force it here as 0 for brotli-st, unless it's specified (e. g. was compressed
   * also multi-threaded, important for -mmt>=1 to use brotli-mt instead of brotli-st)
   */
  decoderSpec->SetNumberOfThreads(!_props._numThreads_WasForced ? 0 : _props._numThreads);
  CMyComPtr<ICompressCoder> decoder = decoderSpec;
  decoderSpec->SetInStream(
    #ifndef _NO_CRYPTO
    _aesStream ? _aesStream :
    #endif
    _seqStream
  );

  CDummyOutStream *outStreamSpec = new CDummyOutStream;
  CMyComPtr<ISequentialOutStream> outStream(outStreamSpec);
  outStreamSpec->SetStream(realOutStream);
  outStreamSpec->Init();

  realOutStream.Release();

  CLocalProgress *lps = new CLocalProgress;
  CMyComPtr<ICompressProgressInfo> progress = lps;
  lps->Init(extractCallback, true);

  UInt64 packSize = 0;
  UInt64 unpackedSize = 0;

  HRESULT result = S_OK;

  for (;;)
  {
    lps->InSize = packSize;
    lps->OutSize = unpackedSize;

    RINOK(lps->SetCur());
    result = decoderSpec->CodeResume(outStream, &unpackedSize, progress);
    UInt64 streamSize = decoderSpec->GetInputProcessedSize();

    if (result != S_FALSE && result != S_OK) {
      if (result == k_My_HRESULT_WritingDone) result = S_OK;
      break;
    }

    if (unpackedSize == 0)
      break;

    if (streamSize == packSize)
    {
      // no new bytes in input stream, So it's good end of archive.
      result = S_OK;
      break;
    }

    if (packSize > streamSize) {
      result = E_FAIL;
      break;
    }
  }

#ifndef _NO_CRYPTO
  _aesStream = NULL; // gets released below
#endif
  decoderSpec->ReleaseInStream();
  outStream.Release();

  if (!_isArc)
    opRes = NExtract::NOperationResult::kIsNotArc;
  else if (_needMoreInput)
    opRes = NExtract::NOperationResult::kUnexpectedEnd;
  else if (_dataAfterEnd)
    opRes = NExtract::NOperationResult::kDataAfterEnd;
  else if (result == S_FALSE)
    opRes = NExtract::NOperationResult::kDataError;
  else if (result == S_OK)
    opRes = NExtract::NOperationResult::kOK;
  else
    return result;

  }

  return extractCallback->SetOperationResult(opRes);

  COM_TRY_END
}

static HRESULT UpdateArchive(
    UInt64 unpackSize,
    ISequentialOutStream *outStream,
    const CProps &props,
    IArchiveUpdateCallback *updateCallback)
{
  HRESULT res;
  #ifndef _NO_CRYPTO
  NCrypto::CAesOutStream *aesStream = NULL;
  CMyComPtr<ICryptoGetTextPassword> getPassword;
  #endif

  RINOK(updateCallback->SetTotal(unpackSize));
  CMyComPtr<ISequentialInStream> fileInStream;
  RINOK(updateCallback->GetStream(0, &fileInStream));
  CLocalProgress *localProgressSpec = new CLocalProgress;
  CMyComPtr<ICompressProgressInfo> localProgress = localProgressSpec;
  localProgressSpec->Init(updateCallback, true);
  NCompress::NBROTLI::CEncoder *encoderSpec = new NCompress::NBROTLI::CEncoder;
  encoderSpec->unpackSize = unpackSize;
  encoderSpec->SetNumberOfThreads(0); /* .br - single threaded processing (without header/mt-frames) */
  CMyComPtr<ICompressCoder> encoder = encoderSpec;
  res = props.SetCoderProps(encoderSpec, NULL);
  if (res != S_OK) goto done;

  // encryption:
  #ifndef _NO_CRYPTO
  updateCallback->QueryInterface(IID_ICryptoGetTextPassword, (void **)&getPassword);
  if (getPassword)
  {
    UString_Wipe password;
    bool passwordIsDefined;
    RINOK(getPassword->CryptoGetPasswordIfAny(passwordIsDefined, password));
    if (passwordIsDefined) {
      aesStream = new NCrypto::CAesOutStream();
      res = aesStream->Init(outStream, password);
      password.Wipe_and_Empty();
      if (res != S_OK) goto done;
      outStream = aesStream;
    }
  }
  #endif

  res = encoder->Code(fileInStream, outStream, NULL, NULL, localProgress);
  if (res != S_OK) goto done;
  res = updateCallback->SetOperationResult(NArchive::NUpdate::NOperationResult::kOK);

done:
  #ifndef _NO_CRYPTO
  if (aesStream) {
    delete aesStream;
  }
  #endif
  return res;
}

Z7_COM7F_IMF(CHandler::GetFileTimeType(UInt32 *type))
{
  *type = NFileTimeType::kUnix;
  return S_OK;
}

Z7_COM7F_IMF(CHandler::UpdateItems(ISequentialOutStream *outStream, UInt32 numItems,
    IArchiveUpdateCallback *updateCallback))
{
  COM_TRY_BEGIN

  if (numItems != 1)
    return E_INVALIDARG;

  Int32 newData, newProps;
  UInt32 indexInArchive;
  if (!updateCallback)
    return E_FAIL;
  RINOK(updateCallback->GetUpdateItemInfo(0, &newData, &newProps, &indexInArchive));
 
  if ((newProps))
  {
    {
      NCOM::CPropVariant prop;
      RINOK(updateCallback->GetProperty(0, kpidIsDir, &prop));
      if (prop.vt != VT_EMPTY)
        if (prop.vt != VT_BOOL || prop.boolVal != VARIANT_FALSE)
          return E_INVALIDARG;
    }
  }
  
  if ((newData))
  {
    UInt64 size;
    {
      NCOM::CPropVariant prop;
      RINOK(updateCallback->GetProperty(0, kpidSize, &prop));
      if (prop.vt != VT_UI8)
        return E_INVALIDARG;
      size = prop.uhVal.QuadPart;
    }
    return UpdateArchive(size, outStream, _props, updateCallback);
  }

  if (indexInArchive != 0)
    return E_INVALIDARG;

  CLocalProgress *lps = new CLocalProgress;
  CMyComPtr<ICompressProgressInfo> progress = lps;
  lps->Init(updateCallback, true);

  CMyComPtr<IArchiveUpdateCallbackFile> opCallback;
  updateCallback->QueryInterface(IID_IArchiveUpdateCallbackFile, (void **)&opCallback);
  if (opCallback)
  {
    RINOK(opCallback->ReportOperation(
        NEventIndexType::kInArcIndex, 0,
        NUpdateNotifyOp::kReplicate))
  }

  if (_stream)
    RINOK(_stream->Seek(0, STREAM_SEEK_SET, NULL));

  return NCompress::CopyStream(_stream, outStream, progress);

  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::SetProperties(const wchar_t * const *names, const PROPVARIANT *values, UInt32 numProps))
{
  return _props.SetProperties(names, values, numProps);
}

IMP_CreateArcIn
IMP_CreateArcOut
REGISTER_ARC_R(
  "brotli", "br brotli tbr", 0, 0x1F,
  0, NULL,
  0,
  NArcInfoFlags::kKeepName | NArcInfoFlags::kPureStartOpen | NArcInfoFlags::kByExtOnlyOpen,
  0,
  CreateArc, CreateArcOut, 
  /* IsArc_Brotli */)
}}
