// 7zAes.h

#ifndef __CRYPTO_AES_STREAM_H
#define __CRYPTO_AES_STREAM_H

#include "../../Common/MyString.h"
#include "../../Common/MyBuffer.h"
#include "../../Common/MyCom.h"
#include "../../Common/MyVector.h"

#include "../ICoder.h"
#include "../IStream.h"
#include "../IPassword.h"
#include "MyAes.h"

namespace NCrypto {

const unsigned kKeySize = 32;
const unsigned kIvSizeMax = AES_BLOCK_SIZE;

class CAesOutStream:
  public ISequentialOutStream,
  public CMyUnknownImp
{
  NCrypto::CAesCoder *_aesFilter;
  ISequentialOutStream *_outStream;

  Byte _Key[kKeySize];
  Byte _iv[kIvSizeMax];

  unsigned _remSize;
  //Byte _remBuf[AES_BLOCK_SIZE];
  CAlignedBuffer _remBuf;
  
public:

  CAesOutStream():
    _aesFilter(NULL),
    _outStream(NULL),
    _remSize(0),
    _remBuf(AES_BLOCK_SIZE)
    {};

  ~CAesOutStream();

  HRESULT Finalize();
  HRESULT Init(ISequentialOutStream *outStream, UString &password);

  MY_UNKNOWN_IMP1(ISequentialOutStream)
  STDMETHOD(Write)(const void *data, UInt32 size, UInt32 *processedSize);
};

}

#endif
