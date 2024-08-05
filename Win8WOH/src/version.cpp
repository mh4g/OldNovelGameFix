
#include <windows.h>
#include <Shlwapi.h>

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

#pragma comment(lib, "Shlwapi.lib")

FARPROC p_GetFileVersionInfoA = NULL;
FARPROC p_GetFileVersionInfoByHandle = NULL;
FARPROC p_GetFileVersionInfoExA = NULL;
FARPROC p_GetFileVersionInfoExW = NULL;
FARPROC p_GetFileVersionInfoSizeA = NULL;
FARPROC p_GetFileVersionInfoSizeExA = NULL;
FARPROC p_GetFileVersionInfoSizeExW = NULL;
FARPROC p_GetFileVersionInfoSizeW = NULL;
FARPROC p_GetFileVersionInfoW = NULL;
FARPROC p_VerFindFileA = NULL;
FARPROC p_VerFindFileW = NULL;
FARPROC p_VerInstallFileA = NULL;
FARPROC p_VerInstallFileW = NULL;
FARPROC p_VerLanguageNameA = NULL;
FARPROC p_VerLanguageNameW = NULL;
FARPROC p_VerQueryValueA = NULL;
FARPROC p_VerQueryValueW = NULL;

__declspec( naked ) void WINAPI d_GetFileVersionInfoA() { _asm{ jmp p_GetFileVersionInfoA } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoByHandle() { _asm{ jmp p_GetFileVersionInfoByHandle } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoExA() { _asm{ jmp p_GetFileVersionInfoExA } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoExW() { _asm{ jmp p_GetFileVersionInfoExW } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoSizeA() { _asm{ jmp p_GetFileVersionInfoSizeA } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoSizeExA() { _asm{ jmp p_GetFileVersionInfoSizeExA } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoSizeExW() { _asm{ jmp p_GetFileVersionInfoSizeExW } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoSizeW() { _asm{ jmp p_GetFileVersionInfoSizeW } }
__declspec( naked ) void WINAPI d_GetFileVersionInfoW() { _asm{ jmp p_GetFileVersionInfoW } }
__declspec( naked ) void WINAPI d_VerFindFileA() { _asm{ jmp p_VerFindFileA } }
__declspec( naked ) void WINAPI d_VerFindFileW() { _asm{ jmp p_VerFindFileW } }
__declspec( naked ) void WINAPI d_VerInstallFileA() { _asm{ jmp p_VerInstallFileA } }
__declspec( naked ) void WINAPI d_VerInstallFileW() { _asm{ jmp p_VerInstallFileW } }
__declspec( naked ) void WINAPI d_VerLanguageNameA() { _asm{ jmp p_VerLanguageNameA } }
__declspec( naked ) void WINAPI d_VerLanguageNameW() { _asm{ jmp p_VerLanguageNameW } }
__declspec( naked ) void WINAPI d_VerQueryValueA() { _asm{ jmp p_VerQueryValueA } }
__declspec( naked ) void WINAPI d_VerQueryValueW() { _asm{ jmp p_VerQueryValueW } }

bool ChangeIAT(HMODULE module);

HMODULE WINAPI d_LoadLibraryA(LPCSTR lpLibFileName) {
  const HMODULE result = ::LoadLibraryA(lpLibFileName);
  if (!ChangeIAT(result)) {
    ::FreeLibrary(result);
    return NULL;
  }
  return result;
}

DWORD WINAPI d_GetModuleFileNameA( __in_opt HMODULE hModule, __out_ecount_part(nSize, return + 1) LPSTR lpFilename, __in DWORD nSize) {
  const DWORD result = ::GetModuleFileNameA(hModule, lpFilename, nSize);
  if (result == 0) {
    return 0;
  }
  const boost::filesystem::path path(lpFilename);
  const boost::filesystem::path fileName = path.filename();
  if (::_stricmp(fileName.string().c_str(), "kernel32.dll") != 0) {
    return result;
  }
  wchar_t dir[MAX_PATH];
  ::GetSystemWow64DirectoryW(dir, _countof(dir));
  const boost::filesystem::path toPath = boost::filesystem::path(dir) / "kernel32.dll";
  ::strcpy_s(lpFilename, nSize, toPath.string().c_str());
  return ::strlen(lpFilename) + 1;
}

bool ChangeIAT(HMODULE module) {
  struct TargetProcInfo {
    std::string dllName;
    std::string procName;
    unsigned int procAddress;
  };
  const TargetProcInfo targetList[] ={
    {"KERNEL32.dll", "GetModuleFileNameA", reinterpret_cast<unsigned int>(d_GetModuleFileNameA)},
    {"KERNEL32.dll", "LoadLibraryA", reinterpret_cast<unsigned int>(d_LoadLibraryA)},
  };
  unsigned char * const baseAddr = reinterpret_cast<unsigned char *>(module == NULL ? ::GetModuleHandleA(NULL) : module);
  const IMAGE_DOS_HEADER &mz = *reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddr);
  const IMAGE_NT_HEADERS32 &pe = *reinterpret_cast<const IMAGE_NT_HEADERS32 *>(baseAddr + mz.e_lfanew);
  const IMAGE_IMPORT_DESCRIPTOR *desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(baseAddr + pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  for (; desc->OriginalFirstThunk != 0; desc = ++desc) {
    const char * const dllName = reinterpret_cast<const char *>(baseAddr + desc->Name);
    const unsigned int *in = reinterpret_cast<unsigned int *>(baseAddr + desc->OriginalFirstThunk);
    unsigned int *out = reinterpret_cast<unsigned int *>(baseAddr + desc->FirstThunk);
    for (; *in != 0; ++in, ++out) {
      if ((*in & 0x80000000) != 0) {
        continue;
      }
      const char * const procName = reinterpret_cast<const char *>(baseAddr + *in + 2);
      BOOST_FOREACH(const TargetProcInfo &target, targetList) {
        if (::_stricmp(target.dllName.c_str(), dllName) != 0 || target.procName != procName) {
          continue;
        }
        DWORD oldProtect;
        ::VirtualProtect(out, 4, PAGE_READWRITE, &oldProtect);
        *out = target.procAddress;
        ::VirtualProtect(out, 4, oldProtect, &oldProtect);
      }
    }
  }
  return true;
}

BOOL APIENTRY DllMain(HANDLE , DWORD ul_reason_for_call, LPVOID) {
  static HMODULE h_original = NULL;
  switch(ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
      if (!ChangeIAT(NULL)) {
        return FALSE;
      }
      wchar_t path[MAX_PATH];
      ::GetSystemDirectoryW(path, _countof(path));
      ::PathAppendW(path, L"version.dll");
      h_original = ::LoadLibraryW(path);
      if(h_original == NULL) {
        return FALSE;
      }
      p_GetFileVersionInfoA = ::GetProcAddress(h_original, "GetFileVersionInfoA");
      p_GetFileVersionInfoByHandle = ::GetProcAddress(h_original, "GetFileVersionInfoByHandle");
      p_GetFileVersionInfoExA = ::GetProcAddress(h_original, "GetFileVersionInfoExA");
      p_GetFileVersionInfoExW = ::GetProcAddress(h_original, "GetFileVersionInfoExW");
      p_GetFileVersionInfoSizeA = ::GetProcAddress(h_original, "GetFileVersionInfoSizeA");
      p_GetFileVersionInfoSizeExA = ::GetProcAddress(h_original, "GetFileVersionInfoSizeExA");
      p_GetFileVersionInfoSizeExW = ::GetProcAddress(h_original, "GetFileVersionInfoSizeExW");
      p_GetFileVersionInfoSizeW = ::GetProcAddress(h_original, "GetFileVersionInfoSizeW");
      p_GetFileVersionInfoW = ::GetProcAddress(h_original, "GetFileVersionInfoW");
      p_VerFindFileA = ::GetProcAddress(h_original, "VerFindFileA");
      p_VerFindFileW = ::GetProcAddress(h_original, "VerFindFileW");
      p_VerInstallFileA = ::GetProcAddress(h_original, "VerInstallFileA");
      p_VerInstallFileW = ::GetProcAddress(h_original, "VerInstallFileW");
      p_VerLanguageNameA = ::GetProcAddress(h_original, "VerLanguageNameA");
      p_VerLanguageNameW = ::GetProcAddress(h_original, "VerLanguageNameW");
      p_VerQueryValueA = ::GetProcAddress(h_original, "VerQueryValueA");
      p_VerQueryValueW = ::GetProcAddress(h_original, "VerQueryValueW");
      break;
    }
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      if(h_original != NULL) {
        ::FreeLibrary(h_original);
      }
      break;
  }
  return TRUE;
}
