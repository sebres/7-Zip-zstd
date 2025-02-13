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

  bool   paddingAdded;
  Byte _Key[kKeySize];
  Byte _iv[kIvSizeMax];

public:

  CAesOutStream():
    _aesFilter(NULL),
    _outStream(NULL),
    paddingAdded(false)
    {};

  ~CAesOutStream();

  HRESULT Init(ISequentialOutStream *outStream, UString &password);

  Z7_COM_UNKNOWN_IMP_1(ISequentialOutStream)
  STDMETHOD(Write)(const void *data, UInt32 size, UInt32 *processedSize);
};

class CAesInStream:
  public ISequentialInStream,
  public CMyUnknownImp
{
  NCrypto::CAesCoder *_aesFilter;
  ISequentialInStream *_inStream;

  Byte _Key[kKeySize];
  Byte _iv[kIvSizeMax];

  bool Eof;
  UInt32 _raheadSize;
  CAlignedBuffer *_raheadBuf;

public:

  CAesInStream():
    _aesFilter(NULL),
    _inStream(NULL),
    Eof(false),
    _raheadSize(0),
    _raheadBuf(NULL)
    {};

  ~CAesInStream();

  HRESULT Init(ISequentialInStream *inStream, UString &password);

  HRESULT ReadAhead(void* data, UInt32 size, UInt32* processedSize);

  Z7_COM_UNKNOWN_IMP_1(ISequentialInStream)
  STDMETHOD(Read)(void *data, UInt32 size, UInt32 *processedSize);
};

}

#endif
