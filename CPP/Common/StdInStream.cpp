// Common/StdInStream.cpp

#include "StdAfx.h"

#ifdef _WIN32
#include <tchar.h>
#endif

#include "StdInStream.h"
#include "StringConvert.h"
#include "UTFConvert.h"
#include <io.h>
#include <fcntl.h>

// #define kEOFMessage "Unexpected end of input stream"
// #define kReadErrorMessage "Error reading input stream"
// #define kIllegalCharMessage "Illegal zero character in input stream"

#define kFileOpenMode TEXT("r")

CStdInStream g_StdIn(stdin);

bool CStdInStream::Open(LPCTSTR fileName) throw()
{
  Close();
  _stream =
    #ifdef _WIN32
      _tfopen
    #else
      fopen
    #endif
      (fileName, kFileOpenMode);
  _streamIsOpen = (_stream != 0);
  return _streamIsOpen;
}

bool CStdInStream::Close() throw()
{
  if (!_streamIsOpen)
    return true;
  _streamIsOpen = (fclose(_stream) != 0);
  return !_streamIsOpen;
}

bool CStdInStream::ScanAStringUntilNewLine(AString &s)
{
  s.Empty();
  for (;;)
  {
    int intChar = GetChar();
    if (intChar == EOF) {
      return ferror(_stream) == 0; // true on eof, false on error
    }
    char c = (char)intChar;
    if (c == '\n')
      return true;
    s += c;
  }
}

bool CStdInStream::ScanUStringUntilNewLine(UString &dest)
{
  dest.Empty();
  int codePage = CodePage;
  if (codePage == -1)
    codePage = CP_OEMCP;
  if (codePage == CP_UNICODE) {
    for (;;)
    {
      wint_t c = fgetwc(_stream);
      if (c == WEOF) {
         return ferror(_stream) == 0; // true on eof, false on error
      }
      if (c == '\n')
        return true;
      dest += (wchar_t)c;
    }
  }
  else {
    AString s;
    bool res = ScanAStringUntilNewLine(s);
    MultiByteToUnicodeString2(dest, s, (UINT)codePage);
    return res;
  }
}

/*
bool CStdInStream::ReadToString(AString &resultString)
{
  resultString.Empty();
  for (;;)
  {
    int intChar = GetChar();
    if (intChar == EOF)
      return !Error();
    char c = (char)intChar;
    if (c == 0)
      return false;
    resultString += c;
  }
}
*/

int CStdInStream::SetCodePage(int codePage)
{
  CodePage = codePage;
  if (codePage == CP_UNICODE) {
    _setmode(_fileno(_stream), _O_WTEXT);
  } else {
    _setmode(_fileno(_stream), _O_TEXT);
  }
  return 0;
}

int CStdInStream::GetChar()
{
  return fgetc(_stream); // getc() doesn't work in BeOS?
}
