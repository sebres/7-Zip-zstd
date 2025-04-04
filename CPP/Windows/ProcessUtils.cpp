// ProcessUtils.cpp

#include "StdAfx.h"

#include "../Common/StringConvert.h"

#include "ProcessUtils.h"

#ifndef _UNICODE
extern bool g_IsNT;
#endif

namespace NWindows {

WRes CProcess::Create(LPCWSTR imageName, const UString &params, LPCWSTR curDir)
{
  /*
  OutputDebugStringW(L"CProcess::Create");
  OutputDebugStringW(imageName);
  if (params)
  {
    OutputDebugStringW(L"params:");
    OutputDebugStringW(params);
  }
  if (curDir)
  {
    OutputDebugStringW(L"cur dir:");
    OutputDebugStringW(curDir);
  }
  */

  Close();
  const UString params2 =
      #ifndef UNDER_CE
      GetQuotedString(imageName) + L' ' +
      #endif
      params;
  #ifdef UNDER_CE
  curDir = NULL;
  #else
  imageName = NULL;
  #endif
  PROCESS_INFORMATION pi;
  BOOL result;
  #ifndef _UNICODE
  if (!g_IsNT)
  {
    STARTUPINFOA si;
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = NULL;
    si.dwFlags = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;
    
    CSysString curDirA;
    if (curDir != 0)
      curDirA = GetSystemString(curDir);
    const AString s = GetSystemString(params2);
    result = ::CreateProcessA(NULL, s.Ptr_non_const(),
        NULL, NULL, FALSE, 0, NULL, ((curDir != 0) ? (LPCSTR)curDirA: 0), &si, &pi);
  }
  else
  #endif
  {
    STARTUPINFOW si;
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpDesktop = NULL;
    si.lpTitle = NULL;
    si.dwFlags = 0;
    si.cbReserved2 = 0;
    si.lpReserved2 = NULL;
    
    result = CreateProcessW(imageName, params2.Ptr_non_const(),
        NULL, NULL, FALSE, 0, NULL, curDir, &si, &pi);
  }
  if (result == 0)
    return ::GetLastError();
  ::CloseHandle(pi.hThread);
  _handle = pi.hProcess;
  return 0;
}

WRes MyCreateProcess(LPCWSTR imageName, const UString &params)
{
  CProcess process;
  return process.Create(imageName, params, NULL);
}

}
