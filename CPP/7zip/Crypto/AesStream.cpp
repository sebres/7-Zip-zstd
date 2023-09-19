// 7zAes.cpp

#include "StdAfx.h"

#include "../Common/StreamUtils.h"

#include "AesStream.h"

// CBC = 0, CTR = 1
#define BMODE_CTR 0

namespace NCrypto {

STDMETHODIMP CAesOutStream::Write(const void *data, UInt32 size, UInt32 *processed)
{
  UInt32 encSize = size;
  // not enough data ?
  if (size < AES_BLOCK_SIZE) {
    if (!this->Finalize) {
      // wait for more data:
      if (processed)
        *processed = 0;
      return S_OK;
    }
  #if !BMODE_CTR
    // CBC mode expects padding to AES_BLOCK_SIZE (16) bytes:
    memset(((Byte *)data)+size, AES_BLOCK_SIZE-size, AES_BLOCK_SIZE-size); // PKCS#7 standard padding
    encSize = AES_BLOCK_SIZE;
  #endif
  }
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
    delete _aesFilter;
  }
}

}
