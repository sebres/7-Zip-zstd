// 7zAes.cpp

#include "StdAfx.h"

#include "../Common/StreamUtils.h"

#include "AesStream.h"

// CBC = 0, CTR = 1
#define BMODE_CTR 0

namespace NCrypto {

#ifndef Z7_EXTRACT_ONLY

Z7_COM7F_IMF(CAesOutStream::Write(const void *data, UInt32 size, UInt32 *processed))
{
  UInt32 encSize = size;
  // not enough data ?
  if (size && size < AES_BLOCK_SIZE) {
    if (!this->Finalize) {
      // wait for more data:
      if (processed)
        *processed = 0;
      return S_OK;
    }
  #if !BMODE_CTR
    // CBC mode expects padding to AES_BLOCK_SIZE (16) bytes:
    if (!paddingAdded) {
      memset(((Byte *)data)+size, AES_BLOCK_SIZE-size, AES_BLOCK_SIZE-size); // PKCS#7 standard padding
      encSize = AES_BLOCK_SIZE;
      paddingAdded = true;
    }
  #endif
  }
  #if !BMODE_CTR
  if (this->Finalize && !paddingAdded && (encSize % AES_BLOCK_SIZE) == 0) {
    // to be compatible to openssl AES-CBC, it expects extra PKCS#7 standard padding (+16 * '\16'),
    // if size was exactly justified to block size:
    memset(((Byte *)data)+size, AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    encSize += AES_BLOCK_SIZE;
    paddingAdded = true;
  }
  #endif
  // encrypt and write next part:
  encSize = _aesFilter->Filter((Byte *)data, encSize);
  HRESULT res = WriteStream(_outStream, data, encSize);
  if (encSize > size)
      encSize = size;
  if (processed)
    *processed = encSize;
  return res;
}

HRESULT CAesOutStream::Init(ISequentialOutStream *outStream, UString &password)
{
  _outStream = outStream;
  // init key/IV from ekey arg:
  if (password.Len() < (32*2+1) || password[0] == PWD_IS_HEX_KEY_MARK) {
    unsigned keyLen = password.HexKeyToBytes(1);
    if (keyLen != kKeySize+sizeof(_iv)) {
      return E_INVALIDARG; // currently only ekey with IV supported
    }
    memcpy(_Key, (Byte*)password.GetBuf(), kKeySize);
    memcpy(_iv, ((Byte*)password.GetBuf())+kKeySize, sizeof(_iv));
  } else {
    return E_NOTIMPL; // currently only ekey with IV supported
  }

  // create AES encoder:
  if (_aesFilter)
    delete _aesFilter;
  #if !BMODE_CTR
  _aesFilter = new CAesCbcEncoder(kKeySize);
  #else
  // currently not implemented
  _aesFilter = new CAesCoder(true, kKeySize, BMODE_CTR); // AES256-CBC or AES256-CTR (currently not compatible to stdandard CTR)
  #endif
  //_aesFilter->SetFunctions(1); // to force software AES encryption

  // init filter:
  RINOK(_aesFilter->SetKey(_Key, sizeof(_Key)));
  RINOK(_aesFilter->SetInitVector(_iv, sizeof(_iv)));
  return _aesFilter->Init();
};

CAesOutStream::~CAesOutStream()
{
  if (_aesFilter) {
    delete _aesFilter;
  }
}

#endif

// ----------------------------------

HRESULT CAesInStream::ReadAhead(void *data, UInt32 size, UInt32 *processedSize)
{
  // read ahead aligned to AES_BLOCK_SIZE (without seek, so the block will be read later again):
  UInt32 s = 0;
  if (_raheadSize + size > AES_BLOCK_SIZE * 2) {
    return E_NOTIMPL;
  }
  if (!Eof) {
    if (!_raheadBuf)
      _raheadBuf = new CAlignedBuffer1(AES_BLOCK_SIZE * 2);
    s = size % AES_BLOCK_SIZE;
    s = !s ? size : size + AES_BLOCK_SIZE - s;
    Byte *buf = (Byte *)*_raheadBuf + _raheadSize;
    size_t rs = s;
    RINOK(ReadStream(_inStream, buf, &rs));
    if (rs < s) {
      Eof = true;
    }
    s = _aesFilter->Filter(buf, (UInt32)rs);
    _raheadSize += s;
    if (data && size <= s) {
      memcpy(data, buf, size);
    }
  }
  if (processedSize) {
    *processedSize = s >= size ? size : s;
  } else {
    if (s < size) {
      return S_FALSE; // by processedSize=NULL it behaves similar to ReadStream_FALSE
    }
  }
  return S_OK;
};

Z7_COM7F_IMF(CAesInStream::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  HRESULT res = S_OK;
  UInt32 procSize = 0, toRead;
  Byte *curData = (Byte *)data;
  size >>= 4; size <<= 4; // align to AES_BLOCK_SIZE;
  toRead = size;
  // if read ahead buffer available - preset it to data and read remaining blocks:
  if (_raheadSize) {
    if (size < _raheadSize) {
      return E_NOTIMPL;
    }
    memcpy(curData, (Byte *)*_raheadBuf, _raheadSize);
    procSize += _raheadSize;
    curData += _raheadSize;
    data = curData; // read ahead buffer is already decrypted
    toRead -= _raheadSize;
    _raheadSize = 0;
  }

  if (Eof) {
    if (processedSize) *processedSize = procSize;
    return S_OK;
  }

  // read:
  UInt32 toDecrypt = 0;
  while (toRead) {
    UInt32 s;
    res = _inStream->Read(curData, toRead, &s);
    if (res != S_OK) {
      goto done;
    }
    if (!s) {
      // eof:
      Eof = true;
      break;
    }
    curData += s;
    toRead -= s;
    toDecrypt += s;
  }
  if (toDecrypt) {
    // decrypt
    if (toDecrypt < AES_BLOCK_SIZE) { // not enough data ?
      if (toRead) { // eof
      #if !BMODE_CTR
        // CBC mode expects padding to AES_BLOCK_SIZE (16) bytes:
        res = E_UNEXPECTED;
        goto done;
      #endif
      }
    }
    // decrypt and return next part:
    procSize += _aesFilter->Filter((Byte *)data, toDecrypt);
  }

#if 0 // don't remove padding here - will be ignored in decoder (do it only once)
  // we need to remove PKCS#7 padding at end, because decompression could
  // try to unpack it as compressed stream (more data after valid frame)...
  if (Eof && procSize >= AES_BLOCK_SIZE) {
    // padding at end of current buffer (last block):
    procSize -= GetPaddingSize(curData);
  }
#endif
done:
  if (processedSize)
    *processedSize = procSize;
  return res;
}

HRESULT CAesInStream::Init(ISequentialInStream *inStream, UString &password)
{
  _inStream = inStream;
  // init key/IV from ekey arg:
  if (password.Len() < (32*2+1) || password[0] == PWD_IS_HEX_KEY_MARK) {
    unsigned keyLen = password.HexKeyToBytes(1);
    if (keyLen != kKeySize+sizeof(_iv)) {
      return E_INVALIDARG; // currently only ekey with IV supported
    }
    memcpy(_Key, (Byte*)password.GetBuf(), kKeySize);
    memcpy(_iv, ((Byte*)password.GetBuf())+kKeySize, sizeof(_iv));
  } else {
    return E_NOTIMPL; // currently only ekey with IV supported
  }

  // create AES encoder:
  if (_aesFilter)
    delete _aesFilter;
  #if !BMODE_CTR
  _aesFilter = new CAesCbcDecoder(kKeySize);
  #else
  // currently not implemented
  _aesFilter = new CAesCoder(false, kKeySize, BMODE_CTR); // AES256-CBC or AES256-CTR (currently not compatible to stdandard CTR)
  #endif
  //_aesFilter->SetFunctions(1); // to force software AES encryption

  // init filter:
  RINOK(_aesFilter->SetKey(_Key, sizeof(_Key)));
  RINOK(_aesFilter->SetInitVector(_iv, sizeof(_iv)));
  return _aesFilter->Init();
};

CAesInStream::~CAesInStream()
{
  if (_aesFilter) {
    delete _aesFilter;
  }
  if (_raheadBuf) {
    delete _raheadBuf;
  }
}


}
