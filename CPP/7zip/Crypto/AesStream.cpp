// 7zAes.cpp

#include "StdAfx.h"

#include "../Common/StreamUtils.h"

#include "AesStream.h"

// CBC = 0, CTR = 1
#define BMODE_CTR 0

namespace NCrypto {

STDMETHODIMP CAesOutStream::Write(const void *data, UInt32 size, UInt32 *processed)
{
  UInt32 totProc = 0;
  // not enough data ?
  if (_remSize + size < AES_BLOCK_SIZE) {
    memcpy((Byte *)_remBuf+_remSize, data, size);
    _remSize += size;
    if (processed)
      *processed = size;
    return S_OK;
  }
  // if remaining buffer present, append with new data:
  if (_remSize) {
    // fill remaining part with new data:
    UInt32 addSize = AES_BLOCK_SIZE-_remSize;
    memcpy((Byte *)_remBuf+_remSize, data, addSize);
    // encrypt remaining part:
    _aesFilter->Filter(_remBuf, AES_BLOCK_SIZE);
    HRESULT res = WriteStream(_outStream, _remBuf, AES_BLOCK_SIZE);
    totProc += addSize;
    size -= addSize;
    if (res != S_OK || !size) { // return if error or no data anymore
      goto done;
    }
    // data must be aligned (to 16 bytes) for HW encryption, thus move data in buffer:
    memmove((void *)data, (Byte*)data + addSize, size);
    _remSize = 0;
  }
  // encrypt and write next part:
  UInt32 encSize = _aesFilter->Filter((Byte *)data, size);
  HRESULT res = WriteStream(_outStream, data, encSize);
  totProc += encSize;
  size -= encSize;
  if (res != S_OK || !size) {
    goto done;
  }
  // store remaining part:
  if (size >= AES_BLOCK_SIZE) {
    return E_UNEXPECTED; // unexpected because remaining size must be smaller than 16 bytes.
  }
  memcpy((Byte *)_remBuf, (Byte*)data + encSize, size);
  _remSize = size;
  totProc += size;
done:
  if (processed)
    *processed = totProc;
  return S_OK;
}

HRESULT CAesOutStream::Finalize()
{
  if (_remSize) {
    // encrypt remaining part:
    #if BMODE_CTR
    _remSize = _aesFilter->Filter(_remBuf, _remSize);
    #else
    // CBC mode expects padding to AES_BLOCK_SIZE (16) bytes:
    if (_remSize < AES_BLOCK_SIZE) {
      memset((Byte *)_remBuf+_remSize, AES_BLOCK_SIZE-_remSize, AES_BLOCK_SIZE-_remSize); // PKCS#7 standard padding
    }
    _remSize = _aesFilter->Filter(_remBuf, AES_BLOCK_SIZE);
    #endif
    HRESULT res = WriteStream(_outStream, (Byte *)_remBuf, _remSize);
    _remSize = 0;
    return res;
  }
  return S_OK;
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
  _aesFilter = new CAesCoder(true, kKeySize, BMODE_CTR); // AES256-CBC or AES256-CTR (currently not compatible to stdandard CTR)
  //_aesFilter->SetFunctions(1); // to force software AES encryption
  //_aesFilter = new CAesCbcEncoder(kKeySize);

  // init filter:
  RINOK(_aesFilter->SetKey(_Key, sizeof(_Key)));
  RINOK(_aesFilter->SetInitVector(_iv, sizeof(_iv)));
  return _aesFilter->Init();
};

CAesOutStream::~CAesOutStream()
{
  if (_aesFilter) {
    Finalize();
    delete _aesFilter;
  }
}

}
