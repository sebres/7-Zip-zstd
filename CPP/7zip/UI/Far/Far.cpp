// Far.cpp
// Test Align for updating !!!!!!!!!!!!!!!!!!

#include "StdAfx.h"

#include "../../../Common/MyWindows.h"
#include "../../../Common/MyInitGuid.h"

#include "../../../Common/StringConvert.h"

#include "../../../Windows/FileDir.h"
#include "../../../Windows/NtCheck.h"

#include "../../Common/FileStreams.h"

#include "Messages.h"
#include "Plugin.h"
#include "ProgressBox.h"

using namespace NWindows;
using namespace NFile;
using namespace NDir;
using namespace NFar;

static const DWORD kShowProgressTime_ms = 100;

static const char * const kCommandPrefix = "7-zip";
static const char * const kRegisrtryMainKeyName = NULL; // ""
static LPCTSTR const kRegisrtryValueNameEnabled = TEXT("UsedByDefault3");
static const char * const kHelpTopicConfig =  "Config";
static bool kPluginEnabledDefault = true;

extern
HINSTANCE g_hInstance;
HINSTANCE g_hInstance;

namespace NFar {

extern
const char *g_PluginName_for_Error;
const char *g_PluginName_for_Error = "7-Zip";

}

#if defined(_UNICODE) && !defined(_WIN64) && !defined(UNDER_CE)
#define NT_CHECK_FAIL_ACTION return FALSE;
#endif

BOOL WINAPI DllMain(
  #ifdef UNDER_CE
    HANDLE
  #else
    HINSTANCE
  #endif
  hInstance, DWORD dwReason, LPVOID);
BOOL WINAPI DllMain(
  #ifdef UNDER_CE
    HANDLE
  #else
    HINSTANCE
  #endif
  hInstance, DWORD dwReason, LPVOID)
{
  if (dwReason == DLL_PROCESS_ATTACH)
  {
    // OutputDebugStringA("7-Zip FAR DLL_PROCESS_ATTACH");
    g_hInstance = (HINSTANCE)hInstance;
    NT_CHECK
  }
  if (dwReason == DLL_PROCESS_DETACH)
  {
    // OutputDebugStringA("7-Zip FAR DLL_PROCESS_DETACH");
  }
  return TRUE;
}

static struct COptions
{
  bool Enabled;
} g_Options;

static const char * const kPliginNameForRegistry = "7-ZIP";

EXTERN_C void WINAPI ExitFAR()
{
  /* WIN32:
       it's not allowed to call FreeLibrary() from FreeLibrary().
       So we try to free all DLLs before destructors */
  // OutputDebugStringA("-- ExitFAR --- START");
  
  FreeGlobalCodecs();

  // OutputDebugStringA("-- ExitFAR --- END");
}

EXTERN_C void WINAPI SetStartupInfo(const PluginStartupInfo *info)
{
  MY_TRY_BEGIN
  g_StartupInfo.Init(*info, kPliginNameForRegistry);
  g_Options.Enabled = g_StartupInfo.QueryRegKeyValue(
      HKEY_CURRENT_USER, kRegisrtryMainKeyName,
      kRegisrtryValueNameEnabled, kPluginEnabledDefault);

  // OutputDebugStringA("SetStartupInfo");
  // LoadGlobalCodecs();

  MY_TRY_END1("SetStartupInfo")
}

Z7_CLASS_IMP_COM_3(
  COpenArchiveCallback
  , IArchiveOpenCallback
  , IProgress
  , ICryptoGetTextPassword
)
  // DWORD m_StartTickValue;
  bool m_MessageBoxIsShown;

  bool _numFilesTotalDefined;
  bool _numBytesTotalDefined;
public:
  bool PasswordIsDefined;
  UString Password;

private:
  CProgressBox _progressBox;
public:

  COpenArchiveCallback()
    {}
  
  void Init()
  {
    PasswordIsDefined = false;

    _numFilesTotalDefined = false;
    _numBytesTotalDefined = false;

    m_MessageBoxIsShown = false;

    _progressBox.Init(
        // g_StartupInfo.GetMsgString(NMessageID::kWaitTitle),
        g_StartupInfo.GetMsgString(NMessageID::kReading));
  }
  void ShowMessage();
};

static HRESULT CheckBreak2()
{
  return WasEscPressed() ? E_ABORT : S_OK;
}

void COpenArchiveCallback::ShowMessage()
{
  if (!m_MessageBoxIsShown)
  {
    DWORD currentTime = GetTickCount();
    if (currentTime - _progressBox.StartTick < kShowProgressTime_ms)
      return;
    m_MessageBoxIsShown = true;
  }

  _progressBox.UseBytesForPercents = !_numFilesTotalDefined;
  _progressBox.Print();
}

Z7_COM7F_IMF(COpenArchiveCallback::SetTotal(const UInt64 *numFiles, const UInt64 *numBytes))
{
  _numFilesTotalDefined = (numFiles != NULL);
  if (_numFilesTotalDefined)
    _progressBox.FilesTotal = *numFiles;

  _numBytesTotalDefined = (numBytes != NULL);
  if (_numBytesTotalDefined)
    _progressBox.Total = *numBytes;

  return CheckBreak2();
}

Z7_COM7F_IMF(COpenArchiveCallback::SetCompleted(const UInt64 *numFiles, const UInt64 *numBytes))
{
  if (numFiles)
    _progressBox.Files = *numFiles;

  if (numBytes)
    _progressBox.Completed = *numBytes;

  ShowMessage();
  return CheckBreak2();
}


Z7_COM7F_IMF(COpenArchiveCallback::SetTotal(const UInt64 /* total */))
{
  return CheckBreak2();
}

Z7_COM7F_IMF(COpenArchiveCallback::SetCompleted(const UInt64 * /* completed */))
{
  ShowMessage();
  return CheckBreak2();
}

HRESULT GetPassword(UString &password);
HRESULT GetPassword(UString &password)
{
  if (WasEscPressed())
    return E_ABORT;
  password.Empty();
  CInitDialogItem initItems[]=
  {
    { DI_DOUBLEBOX, 3, 1, 72, 4, false, false, 0, false,  NMessageID::kGetPasswordTitle, NULL, NULL },
    { DI_TEXT, 5, 2, 0, 0, false, false, DIF_SHOWAMPERSAND, false, NMessageID::kEnterPasswordForFile, NULL, NULL },
    { DI_PSWEDIT, 5, 3, 70, 3, true, false, 0, true, -1, "", NULL }
  };
  
  const int kNumItems = Z7_ARRAY_SIZE(initItems);
  FarDialogItem dialogItems[kNumItems];
  g_StartupInfo.InitDialogItems(initItems, dialogItems, kNumItems);
  
  // sprintf(DialogItems[1].Data,GetMsg(MGetPasswordForFile),FileName);
  if (g_StartupInfo.ShowDialog(76, 6, NULL, dialogItems, kNumItems) < 0)
    return E_ABORT;

  password = MultiByteToUnicodeString(dialogItems[2].Data, CP_OEMCP);
  return S_OK;
}

Z7_COM7F_IMF(COpenArchiveCallback::CryptoGetTextPassword(BSTR *password))
{
  if (!PasswordIsDefined)
  {
    RINOK(GetPassword(Password))
    PasswordIsDefined = true;
  }
  return StringToBstr(Password, password);
}

Z7_COM7F_IMF(COpenArchiveCallback::CryptoGetPasswordIfAny(bool& passwordIsDefined, UString& password))
{
  passwordIsDefined = PasswordIsDefined;
  password = Password;
  return S_OK;
}

/*
HRESULT OpenArchive(const CSysString &fileName,
    IInFolderArchive **archiveHandlerResult,
    CArchiverInfo &archiverInfoResult,
    UString &defaultName,
    IArchiveOpenCallback *openArchiveCallback)
{
  HRESULT OpenArchive(const CSysString &fileName,
    IInArchive **archive,
    CArchiverInfo &archiverInfoResult,
    IArchiveOpenCallback *openArchiveCallback);
}
*/

static HANDLE MyOpenFilePluginW(const wchar_t *name, bool isAbortCodeSupported)
{
  FString normalizedName = us2fs(name);
  normalizedName.Trim();
  FString fullName;
  MyGetFullPathName(normalizedName, fullName);
  NFind::CFileInfo fileInfo;
  if (!fileInfo.Find(fullName))
    return INVALID_HANDLE_VALUE;
  if (fileInfo.IsDir())
    return INVALID_HANDLE_VALUE;


  CMyComPtr<IInFolderArchive> archiveHandler;

  // CArchiverInfo archiverInfoResult;
  // ::OutputDebugStringA("before OpenArchive\n");
  
  CScreenRestorer screenRestorer;
  {
    screenRestorer.Save();
  }

  COpenArchiveCallback *openArchiveCallbackSpec = new COpenArchiveCallback;
  CMyComPtr<IArchiveOpenCallback> uiCallback = openArchiveCallbackSpec;

  /* COpenCallbackImp object will exist after Open stage for multivolume archioves */
  COpenCallbackImp *impSpec = new COpenCallbackImp;
  CMyComPtr<IArchiveOpenCallback> impCallback = impSpec;
  impSpec->ReOpenCallback = openArchiveCallbackSpec; // we set pointer without reference counter

  // if ((opMode & OPM_SILENT) == 0 && (opMode & OPM_FIND ) == 0)
  openArchiveCallbackSpec->Init();
  {
    FString dirPrefix, fileName;
    GetFullPathAndSplit(fullName, dirPrefix, fileName);
    impSpec->Init2(dirPrefix, fileName);
  }
  
  // ::OutputDebugStringA("before OpenArchive\n");
  
  CAgent *agent = new CAgent;
  archiveHandler = agent;
  CMyComBSTR archiveType;
  HRESULT result = archiveHandler->Open(NULL,
      GetUnicodeString(fullName, CP_OEMCP), UString(), &archiveType, impCallback);
  /*
  HRESULT result = ::OpenArchive(fullName, &archiveHandler,
      archiverInfoResult, defaultName, openArchiveCallback);
  */
  if (result == E_ABORT)
  {
    // fixed 18.06:
    // OpenFilePlugin() is allowed to return (HANDLE)-2 as abort code
    // OpenPlugin() is not allowed to return (HANDLE)-2.
    return isAbortCodeSupported ? (HANDLE)-2 : INVALID_HANDLE_VALUE;
  }

  UString errorMessage = agent->GetErrorMessage();
  if (!errorMessage.IsEmpty())
    g_StartupInfo.ShowErrorMessage(UnicodeStringToMultiByte(errorMessage, CP_OEMCP));

  if (result != S_OK)
  {
    if (result == S_FALSE)
      return INVALID_HANDLE_VALUE;
    ShowSysErrorMessage(result);
    return INVALID_HANDLE_VALUE;
  }

  // ::OutputDebugStringA("after OpenArchive\n");

  CPlugin *plugin = new CPlugin(
      fullName,
      // defaultName,
      agent,
      (const wchar_t *)archiveType
      );

  plugin->PasswordIsDefined = openArchiveCallbackSpec->PasswordIsDefined;
  plugin->Password = openArchiveCallbackSpec->Password;

  // OutputDebugStringA("--- OpenFilePlugin ---- END");
  return (HANDLE)(plugin);
}

static HANDLE MyOpenFilePlugin(const char *name, bool isAbortCodeSupported)
{
  UINT codePage =
  #ifdef UNDER_CE
    CP_OEMCP;
  #else
    ::AreFileApisANSI() ? CP_ACP : CP_OEMCP;
  #endif
  return MyOpenFilePluginW(GetUnicodeString(name, codePage), isAbortCodeSupported);
}

EXTERN_C HANDLE WINAPI OpenFilePlugin(char *name, const Byte * /* data */, int /* dataSize */)
{
  MY_TRY_BEGIN
  // OutputDebugStringA("--- OpenFilePlugin");
  if (name == NULL || (!g_Options.Enabled))
  {
    // if (!Opt.ProcessShiftF1)
      return(INVALID_HANDLE_VALUE);
  }
  return MyOpenFilePlugin(name, true); // isAbortCodeSupported
  MY_TRY_END2("OpenFilePlugin", INVALID_HANDLE_VALUE)
}

/*
EXTERN_C HANDLE WINAPI OpenFilePluginW(const wchar_t *name,const Byte *Data,int DataSize,int OpMode)
{
  MY_TRY_BEGIN
  if (name == NULL || (!g_Options.Enabled))
  {
    // if (!Opt.ProcessShiftF1)
      return(INVALID_HANDLE_VALUE);
  }
  return MyOpenFilePluginW(name);
  ::OutputDebugStringA("OpenFilePluginW\n");
  MY_TRY_END2("OpenFilePluginW", INVALID_HANDLE_VALUE);
}
*/

EXTERN_C HANDLE WINAPI OpenPlugin(int openFrom, INT_PTR item)
{
  MY_TRY_BEGIN
  
  if (openFrom == OPEN_COMMANDLINE)
  {
    AString fileName ((const char *)item);
    if (fileName.IsEmpty())
      return INVALID_HANDLE_VALUE;
    if (fileName.Len() >= 2
        && fileName[0] == '\"'
        && fileName.Back() == '\"')
    {
      fileName.DeleteBack();
      fileName.DeleteFrontal(1);
    }
    return MyOpenFilePlugin(fileName, false); // isAbortCodeSupported
  }
  
  if (openFrom == OPEN_PLUGINSMENU)
  {
    switch (item)
    {
      case 0:
      {
        PluginPanelItem pluginPanelItem;
        if (!g_StartupInfo.ControlGetActivePanelCurrentItemInfo(pluginPanelItem))
          throw 142134;
        return MyOpenFilePlugin(pluginPanelItem.FindData.cFileName, false); // isAbortCodeSupported
      }
      
      case 1:
      {
        CObjectVector<PluginPanelItem> pluginPanelItem;
        if (!g_StartupInfo.ControlGetActivePanelSelectedOrCurrentItems(pluginPanelItem))
          throw 142134;
        HRESULT res = CompressFiles(pluginPanelItem);
        if (res != S_OK && res != E_ABORT)
        {
          ShowSysErrorMessage(res);
        }
        // if (res == S_OK)
        {
          /* int t = */ g_StartupInfo.ControlClearPanelSelection();
          g_StartupInfo.ControlRequestActivePanel(FCTL_UPDATEPANEL, NULL);
          g_StartupInfo.ControlRequestActivePanel(FCTL_REDRAWPANEL, NULL);
          g_StartupInfo.ControlRequestActivePanel(FCTL_UPDATEANOTHERPANEL, NULL);
          g_StartupInfo.ControlRequestActivePanel(FCTL_REDRAWANOTHERPANEL, NULL);
        }
        return INVALID_HANDLE_VALUE;
      }
      
      default:
        throw 4282215;
    }
  }

  return INVALID_HANDLE_VALUE;
  MY_TRY_END2("OpenPlugin", INVALID_HANDLE_VALUE)
}

EXTERN_C void WINAPI ClosePlugin(HANDLE plugin)
{
  // OutputDebugStringA("-- ClosePlugin --- START");
  // MY_TRY_BEGIN
  delete (CPlugin *)plugin;
  // OutputDebugStringA("-- ClosePlugin --- END");
  // MY_TRY_END1("ClosePlugin");
}

EXTERN_C int WINAPI GetFindData(HANDLE plugin, struct PluginPanelItem **panelItems, int *itemsNumber, int opMode)
{
  MY_TRY_BEGIN
  return(((CPlugin *)plugin)->GetFindData(panelItems, itemsNumber, opMode));
  MY_TRY_END2("GetFindData", FALSE)
}

EXTERN_C void WINAPI FreeFindData(HANDLE plugin, struct PluginPanelItem *panelItems, int itemsNumber)
{
  // MY_TRY_BEGIN
  ((CPlugin *)plugin)->FreeFindData(panelItems, itemsNumber);
  // MY_TRY_END1("FreeFindData");
}

EXTERN_C int WINAPI GetFiles(HANDLE plugin, struct PluginPanelItem *panelItems,
    int itemsNumber, int move, char *destPath, int opMode)
{
  MY_TRY_BEGIN
  return(((CPlugin *)plugin)->GetFiles(panelItems, (unsigned)itemsNumber, move, destPath, opMode));
  MY_TRY_END2("GetFiles", NFileOperationReturnCode::kError)
}

EXTERN_C int WINAPI SetDirectory(HANDLE plugin, const char *dir, int opMode)
{
  MY_TRY_BEGIN
  return(((CPlugin *)plugin)->SetDirectory(dir, opMode));
  MY_TRY_END2("SetDirectory", FALSE)
}

EXTERN_C void WINAPI GetPluginInfo(struct PluginInfo *info)
{
  MY_TRY_BEGIN

  info->StructSize = sizeof(*info);
  info->Flags = 0;
  info->DiskMenuStrings = NULL;
  info->DiskMenuNumbers = NULL;
  info->DiskMenuStringsNumber = 0;
  static char *pluginMenuStrings[2];
  pluginMenuStrings[0] = const_cast<char *>(g_StartupInfo.GetMsgString(NMessageID::kOpenArchiveMenuString));
  pluginMenuStrings[1] = const_cast<char *>(g_StartupInfo.GetMsgString(NMessageID::kCreateArchiveMenuString));
  info->PluginMenuStrings = (char **)pluginMenuStrings;
  info->PluginMenuStringsNumber = 2;
  static char *pluginCfgStrings[1];
  pluginCfgStrings[0] = const_cast<char *>(g_StartupInfo.GetMsgString(NMessageID::kOpenArchiveMenuString));
  info->PluginConfigStrings = (char **)pluginCfgStrings;
  info->PluginConfigStringsNumber = Z7_ARRAY_SIZE(pluginCfgStrings);
  info->CommandPrefix = const_cast<char *>(kCommandPrefix);
  MY_TRY_END1("GetPluginInfo")
}

EXTERN_C int WINAPI Configure(int /* itemNumber */)
{
  MY_TRY_BEGIN

  const int kEnabledCheckBoxIndex = 1;

  const int kYSize = 7;

  struct CInitDialogItem initItems[]=
  {
    { DI_DOUBLEBOX, 3, 1, 72, kYSize - 2, false, false, 0, false, NMessageID::kConfigTitle, NULL, NULL },
    { DI_CHECKBOX, 5, 2, 0, 0, true, g_Options.Enabled, 0, false, NMessageID::kConfigPluginEnabled, NULL, NULL },
    { DI_TEXT, 5, 3, 0, 0, false, false, DIF_BOXCOLOR | DIF_SEPARATOR, false, -1, "", NULL },
    { DI_BUTTON, 0, kYSize - 3, 0, 0, false, false, DIF_CENTERGROUP, true, NMessageID::kOk, NULL, NULL },
    { DI_BUTTON, 0, kYSize - 3, 0, 0, false, false, DIF_CENTERGROUP, false, NMessageID::kCancel, NULL, NULL },
  };

  const int kNumDialogItems = Z7_ARRAY_SIZE(initItems);
  const int kOkButtonIndex = kNumDialogItems - 2;

  FarDialogItem dialogItems[kNumDialogItems];
  g_StartupInfo.InitDialogItems(initItems, dialogItems, kNumDialogItems);

  int askCode = g_StartupInfo.ShowDialog(76, kYSize,
      kHelpTopicConfig, dialogItems, kNumDialogItems);

  if (askCode != kOkButtonIndex)
    return (FALSE);

  g_Options.Enabled = BOOLToBool(dialogItems[kEnabledCheckBoxIndex].Selected);

  g_StartupInfo.SetRegKeyValue(HKEY_CURRENT_USER, kRegisrtryMainKeyName,
      kRegisrtryValueNameEnabled, g_Options.Enabled);
  return(TRUE);
  MY_TRY_END2("Configure", FALSE)
}

EXTERN_C void WINAPI GetOpenPluginInfo(HANDLE plugin,struct OpenPluginInfo *info)
{
  MY_TRY_BEGIN
  ((CPlugin *)plugin)->GetOpenPluginInfo(info);
  MY_TRY_END1("GetOpenPluginInfo")
}

EXTERN_C int WINAPI PutFiles(HANDLE plugin, struct PluginPanelItem *panelItems, int itemsNumber, int move, int opMode)
{
  MY_TRY_BEGIN
  return (((CPlugin *)plugin)->PutFiles(panelItems, (unsigned)itemsNumber, move, opMode));
  MY_TRY_END2("PutFiles", NFileOperationReturnCode::kError)
}

EXTERN_C int WINAPI DeleteFiles(HANDLE plugin, PluginPanelItem *panelItems, int itemsNumber, int opMode)
{
  MY_TRY_BEGIN
  return (((CPlugin *)plugin)->DeleteFiles(panelItems, (unsigned)itemsNumber, opMode));
  MY_TRY_END2("DeleteFiles", FALSE)
}

EXTERN_C int WINAPI ProcessKey(HANDLE plugin, int key, unsigned controlState)
{
  MY_TRY_BEGIN
  /* FIXME: after folder creation with F7, it doesn't reload new file list
     We need some to reload it */
  return (((CPlugin *)plugin)->ProcessKey(key, controlState));
  MY_TRY_END2("ProcessKey", FALSE)
}

/*
struct MakeDirectoryInfo
{
  size_t StructSize;
  HANDLE hPanel;
  const wchar_t *Name;
  OPERATION_MODES OpMode;
  void* Instance;
};

typedef INT_PTR MY_intptr_t;

MY_intptr_t WINAPI MakeDirectoryW(struct MakeDirectoryInfo *Info)
{
  MY_TRY_BEGIN
  if (Info->StructSize < sizeof(MakeDirectoryInfo))
  {
    return 0;
  }
  return 0;
  MY_TRY_END2("MakeDirectoryW", FALSE);
}
*/
