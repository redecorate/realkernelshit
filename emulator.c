#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>
#include <tlhelp32.h>
#include "MinHook.h"

#define EMU_FAKE_HANDLE_VALUE    ((HANDLE)(ULONG_PTR)0x1757C004)
#define EMU_FAKE_SYMLINK_HANDLE  ((HANDLE)(ULONG_PTR)0x1757CC01)
#define EMU_FAKE_DRIVER_BASE     0xFFFFF8031C400000ULL /* stand-in relocated .sys base */
#define EMU_FAKE_RETURN_ADDR     0xFFFFF8030E2A51F0ULL /* stand-in for the 0x3820 leak */
#define EMU_DRIVER_IMAGE_LIMIT   0x4220   /* validator upper bound (findings section 6.C) */
#define EMU_DRIVER_OOB_BOUNDARY  0x18F0   /* validator forbidden crossing point   */
#define EMU_MAX_TRANSFORM_LEN    0x1000000 /* deviation: cap pathological lengths  */

#define IOCTL_REG_PATH        0xAA023800 /* in  >=0x208 : set global path, activate   */
#define IOCTL_DISABLE_ENF     0xAA023804 /* in  0       : enabled = 0                 */
#define IOCTL_ENABLE_ENF      0xAA023808 /* in  0       : enabled = 1                 */
#define IOCTL_SET_TRUSTED5    0xAA02380C /* in  0x14    : five trusted caller PIDs    */
#define IOCTL_SET_PARENTS3    0xAA023810 /* in  0x0C    : three parent-PID values     */
#define IOCTL_SET_SVC_PARENT  0xAA023814 /* in  0x04    : svchost parent PID          */
#define IOCTL_GET_TELEMETRY   0xAA023818 /* out 0x30    : consume+clear 12 DWORDs     */
#define IOCTL_GET_VERSION     0xAA02381C /* out 0x04    : returns 0x44C               */
#define IOCTL_GET_RETADDR     0xAA023820 /* out 0x08    : kernel return-address leak  */
#define IOCTL_GET_TOKEN_BASE  0xAA023824 /* out 0x10    : PID token + image base      */
#define IOCTL_AUTH_RESPONSE   0xAA023828 /* in  0x04    : auth transition             */
#define IOCTL_INTEGRITY       0xAA02382C /* in  0x08/out 0x04 : integrity transform  */

#define EMU_PROTOCOL_VERSION  0x44C
#define EMU_READY_COOKIE      0x484F4C4F454D5531ULL

__declspec(dllexport) volatile ULONGLONG g_EmulatorReadyCookie = 0;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER      ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED          ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL       ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH   ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND  ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES        ((NTSTATUS)0x8000001AL)
#endif

/* Hook types */

typedef HANDLE   (WINAPI *pCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD    (WINAPI *pGetFileAttributesW)(LPCWSTR);
typedef BOOL     (WINAPI *pGetFileAttributesExW)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
typedef DWORD    (WINAPI *pQueryDosDeviceW)(LPCWSTR, LPWSTR, DWORD);
typedef BOOL     (WINAPI *pDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL     (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL     (WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef NTSTATUS (NTAPI *pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtQueryAttributesFile)(POBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS (NTAPI *pNtQueryFullAttributesFile)(POBJECT_ATTRIBUTES, PVOID);
typedef NTSTATUS (NTAPI *pNtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);

typedef SC_HANDLE (WINAPI *pOpenServiceW)(SC_HANDLE, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *pOpenServiceA)(SC_HANDLE, LPCSTR, DWORD);
typedef SC_HANDLE (WINAPI *pCreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef SC_HANDLE (WINAPI *pCreateServiceA)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
typedef BOOL (WINAPI *pStartServiceW)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL (WINAPI *pStartServiceA)(SC_HANDLE, DWORD, LPCSTR*);
typedef BOOL (WINAPI *pQueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
typedef BOOL (WINAPI *pQueryServiceStatusEx)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
typedef BOOL (WINAPI *pQueryServiceConfigW)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
typedef BOOL (WINAPI *pQueryServiceConfigA)(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
typedef BOOL (WINAPI *pEnumServicesStatusExW)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
typedef BOOL (WINAPI *pEnumServicesStatusExA)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
typedef BOOL (WINAPI *pControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
typedef BOOL (WINAPI *pDeleteService)(SC_HANDLE);
typedef BOOL (WINAPI *pCloseServiceHandle)(SC_HANDLE);
typedef BOOL (WINAPI *pChangeServiceConfigW)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL (WINAPI *pChangeServiceConfigA)(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
typedef NTSTATUS (NTAPI *pNtLoadDriver)(PUNICODE_STRING);

typedef NTSTATUS (NTAPI *pNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtRaiseException)(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);
typedef BOOL     (WINAPI *pTerminateProcess)(HANDLE, UINT);
typedef NTSTATUS (NTAPI *pNtTerminateProcess)(HANDLE, NTSTATUS);
typedef void     (NTAPI *pRtlExitUserProcess)(NTSTATUS);
typedef NTSTATUS (NTAPI *pNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtOpenKeyEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *pNtQueryValueKey)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtQueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtEnumerateKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtEnumerateValueKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtOpenSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtQuerySymbolicLinkObject)(HANDLE, PUNICODE_STRING, PULONG);
typedef NTSTATUS (NTAPI *pNtResumeThread)(HANDLE, PULONG);

static pCreateFileW           OriginalCreateFileW           = NULL;
static pGetFileAttributesW    OriginalGetFileAttributesW    = NULL;
static pGetFileAttributesExW  OriginalGetFileAttributesExW  = NULL;
static pQueryDosDeviceW       OriginalQueryDosDeviceW       = NULL;
static pDeviceIoControl       OriginalDeviceIoControl       = NULL;
static pCloseHandle           OriginalCloseHandle           = NULL;
static pCreateProcessW        OriginalCreateProcessW        = NULL;
static pNtCreateFile          OriginalNtCreateFile          = NULL;
static pNtQueryAttributesFile OriginalNtQueryAttributesFile = NULL;
static pNtQueryFullAttributesFile OriginalNtQueryFullAttributesFile = NULL;
static pNtDeviceIoControlFile OriginalNtDeviceIoControlFile = NULL;
static pNtClose               OriginalNtClose               = NULL;
static pNtCreateUserProcess   OriginalNtCreateUserProcess   = NULL;

static pOpenServiceW          OriginalOpenServiceW          = NULL;
static pOpenServiceA          OriginalOpenServiceA          = NULL;
static pCreateServiceW        OriginalCreateServiceW        = NULL;
static pCreateServiceA        OriginalCreateServiceA        = NULL;
static pStartServiceW         OriginalStartServiceW         = NULL;
static pStartServiceA         OriginalStartServiceA         = NULL;
static pQueryServiceStatus    OriginalQueryServiceStatus    = NULL;
static pQueryServiceStatusEx  OriginalQueryServiceStatusEx  = NULL;
static pQueryServiceConfigW   OriginalQueryServiceConfigW   = NULL;
static pQueryServiceConfigA   OriginalQueryServiceConfigA   = NULL;
static pEnumServicesStatusExW OriginalEnumServicesStatusExW = NULL;
static pEnumServicesStatusExA OriginalEnumServicesStatusExA = NULL;
static pControlService        OriginalControlService        = NULL;
static pDeleteService         OriginalDeleteService         = NULL;
static pCloseServiceHandle    OriginalCloseServiceHandle    = NULL;
static pChangeServiceConfigW  OriginalChangeServiceConfigW  = NULL;
static pChangeServiceConfigA  OriginalChangeServiceConfigA  = NULL;
static pNtLoadDriver          OriginalNtLoadDriver          = NULL;

static pNtOpenFile            OriginalNtOpenFile            = NULL;
static pNtQuerySystemInformation OriginalNtQuerySystemInformation = NULL;
static pNtRaiseException      OriginalNtRaiseException      = NULL;
static pTerminateProcess      OriginalTerminateProcess      = NULL;
static pNtTerminateProcess    OriginalNtTerminateProcess    = NULL;
static pRtlExitUserProcess    OriginalRtlExitUserProcess    = NULL;
static pNtOpenKey             OriginalNtOpenKey             = NULL;
static pNtOpenKeyEx           OriginalNtOpenKeyEx           = NULL;
static pNtQueryValueKey       OriginalNtQueryValueKey       = NULL;
static pNtQueryKey            OriginalNtQueryKey            = NULL;
static pNtEnumerateKey        OriginalNtEnumerateKey        = NULL;
static pNtEnumerateValueKey   OriginalNtEnumerateValueKey   = NULL;
static pNtOpenSymbolicLinkObject OriginalNtOpenSymbolicLinkObject = NULL;
static pNtQuerySymbolicLinkObject OriginalNtQuerySymbolicLinkObject = NULL;
static pNtResumeThread          OriginalNtResumeThread          = NULL;
static LONG                     g_ExitStackLogged               = 0;

extern NTSTATUS NTAPI EmuNtQuerySystemInformationThunk(
    ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS NTAPI EmuNtTerminateProcessThunk(HANDLE, NTSTATUS);
extern NTSTATUS NTAPI EmuNtRaiseExceptionThunk(
    PEXCEPTION_RECORD, PCONTEXT, BOOLEAN);

static HMODULE g_hModule = NULL;
static char    g_LogPath[MAX_PATH] = "emulator.log";
static BOOL    g_TraceEnabled = FALSE;
static BOOL    g_ForceVirtualService = FALSE;
static BOOL    g_IsWine = FALSE;
typedef struct _EMU_STATE {
    BOOL     handle_open;
    UINT16   auth_state;
    UINT8    enabled;
    UINT8    active;
    ULONG32  trusted_pid[5];
    ULONG32  parent_pid[3];
    ULONG32  svchost_parent_pid;
    ULONG32  telemetry[12];
    WCHAR    global_path[260];
} EMU_STATE;

static EMU_STATE        g_State;
static CRITICAL_SECTION g_Lock;

static PUCHAR  g_SysBytes       = NULL;
static SIZE_T  g_SysBytesSize   = 0;
static ULONG32 g_SysImageSize   = 0;
static ULONG32 g_SysHeadersSize = 0;
typedef struct _EMU_SECTION {
    ULONG32 vaStart;
    ULONG32 vaEnd;
    ULONG32 rawStart;
    ULONG32 rawSize;
} EMU_SECTION;
static EMU_SECTION g_Sections[32];
static int         g_SectionCount = 0;
static LONG        g_CrashLogged = 0;

static BOOL EmuEnvironmentFlag(const char* name) {
    char value[16];
    DWORD length = GetEnvironmentVariableA(name, value, ARRAYSIZE(value));
    if (!length || length >= ARRAYSIZE(value)) return FALSE;
    return _stricmp(value, "0") != 0 &&
           _stricmp(value, "false") != 0 &&
           _stricmp(value, "off") != 0 &&
           _stricmp(value, "no") != 0;
}

static void EmuInitializeConfiguration(void) {
    DWORD length = GetEnvironmentVariableA(
        "HOLO_EMU_LOG", g_LogPath, ARRAYSIZE(g_LogPath));
    if (!length || length >= ARRAYSIZE(g_LogPath)) {
        char* slash;
        length = GetModuleFileNameA(
            g_hModule, g_LogPath, ARRAYSIZE(g_LogPath));
        if (!length || length >= ARRAYSIZE(g_LogPath)) {
            strcpy_s(g_LogPath, ARRAYSIZE(g_LogPath), "emulator.log");
        } else {
            slash = strrchr(g_LogPath, '\\');
            if (!slash) slash = strrchr(g_LogPath, '/');
            if (slash) {
                strcpy_s(slash + 1,
                         ARRAYSIZE(g_LogPath) -
                             (SIZE_T)(slash + 1 - g_LogPath),
                         "emulator.log");
            } else {
                strcpy_s(g_LogPath, ARRAYSIZE(g_LogPath), "emulator.log");
            }
        }
    }
    g_TraceEnabled = EmuEnvironmentFlag("HOLO_EMU_TRACE");
    g_ForceVirtualService =
        EmuEnvironmentFlag("HOLO_EMU_FORCE_VIRTUAL_SERVICE");
}

void LogMessage(const char* format, ...) {
    FILE* f;
    fopen_s(&f, g_LogPath, "a");
    if (f) {
        fprintf(f, "[%llu pid=%lu tid=%lu] ",
                (unsigned long long)(GetTickCount64() / 1000),
                GetCurrentProcessId(),
                GetCurrentThreadId());
        va_list args; va_start(args, format); vfprintf(f, format, args); va_end(args);
        fprintf(f, "\n"); fclose(f);
    }
}

static void EmuLogAddress(const char* label, const void* address) {
    HMODULE module = NULL;
    if (address &&
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)address, &module) &&
        module) {
        char modulePath[MAX_PATH];
        char* moduleName;
        GetModuleFileNameA(module, modulePath, MAX_PATH);
        moduleName = strrchr(modulePath, '\\');
        LogMessage("[Emu] %s %s+0x%llX", label,
                   moduleName ? moduleName + 1 : modulePath,
                   (unsigned long long)((ULONG_PTR)address -
                                        (ULONG_PTR)module));
    } else {
        LogMessage("[Emu] %s %p (unbacked)", label, address);
    }
}

static LONG CALLBACK EmuCrashObserver(PEXCEPTION_POINTERS pointers) {
    PEXCEPTION_RECORD record;
    PCONTEXT context;
    ULONG_PTR accessType = 0;
    ULONG_PTR accessAddress = 0;
    ULONG_PTR* stack;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T readableBytes = 0;
    SIZE_T i;

    if (!pointers || !pointers->ExceptionRecord || !pointers->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    record = pointers->ExceptionRecord;
    context = pointers->ContextRecord;
    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        record->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
        record->ExceptionCode != EXCEPTION_STACK_OVERFLOW)
        return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedCompareExchange(&g_CrashLogged, 1, 0) != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        record->NumberParameters >= 2) {
        accessType = record->ExceptionInformation[0];
        accessAddress = record->ExceptionInformation[1];
    }

    LogMessage("[Emu] CRASH code=0x%08lX flags=0x%08lX "
               "access_type=%llu access_address=%p RIP=%p RSP=%p "
               "RBP=%p rsp_align=%llu",
               (ULONG)record->ExceptionCode,
               (ULONG)record->ExceptionFlags,
               (unsigned long long)accessType,
               (void*)accessAddress,
               (void*)context->Rip,
               (void*)context->Rsp,
               (void*)context->Rbp,
               (unsigned long long)(context->Rsp & 0xFULL));
    LogMessage("[Emu]   registers: RAX=%p RBX=%p RCX=%p RDX=%p "
               "RSI=%p RDI=%p",
               (void*)context->Rax, (void*)context->Rbx,
               (void*)context->Rcx, (void*)context->Rdx,
               (void*)context->Rsi, (void*)context->Rdi);
    LogMessage("[Emu]   registers: R8=%p R9=%p R10=%p R11=%p "
               "R12=%p R13=%p R14=%p R15=%p",
               (void*)context->R8,  (void*)context->R9,
               (void*)context->R10, (void*)context->R11,
               (void*)context->R12, (void*)context->R13,
               (void*)context->R14, (void*)context->R15);
    EmuLogAddress("crash site:", (void*)context->Rip);

    stack = (ULONG_PTR*)context->Rsp;
    if (VirtualQuery(stack, &mbi, sizeof(mbi)) == sizeof(mbi) &&
        mbi.State == MEM_COMMIT &&
        !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
        readableBytes = (SIZE_T)((ULONG_PTR)mbi.BaseAddress +
                                 mbi.RegionSize -
                                 (ULONG_PTR)stack);
        if (readableBytes > 0x400)
            readableBytes = 0x400;
    }

    for (i = 0; i < readableBytes / sizeof(ULONG_PTR); i++) {
        ULONG_PTR candidate = stack[i];
        HMODULE module = NULL;
        if (candidate &&
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)candidate, &module) &&
            module) {
            char modulePath[MAX_PATH];
            char* moduleName;
            GetModuleFileNameA(module, modulePath, MAX_PATH);
            moduleName = strrchr(modulePath, '\\');
            LogMessage("[Emu]   crash stack +0x%03llX: %s+0x%llX",
                       (unsigned long long)(i * sizeof(ULONG_PTR)),
                       moduleName ? moduleName + 1 : modulePath,
                       (unsigned long long)(candidate -
                                            (ULONG_PTR)module));
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static const char* EmuIoctlName(ULONG code) {
    switch (code) {
    case IOCTL_REG_PATH:       return "0x3800 REGISTER_PATH";
    case IOCTL_DISABLE_ENF:    return "0x3804 DISABLE_ENFORCEMENT";
    case IOCTL_ENABLE_ENF:     return "0x3808 ENABLE_ENFORCEMENT";
    case IOCTL_SET_TRUSTED5:   return "0x380C SET_TRUSTED_PIDS";
    case IOCTL_SET_PARENTS3:   return "0x3810 SET_PARENT_PIDS";
    case IOCTL_SET_SVC_PARENT: return "0x3814 SET_SVCHOST_PARENT";
    case IOCTL_GET_TELEMETRY:  return "0x3818 GET_TELEMETRY";
    case IOCTL_GET_VERSION:    return "0x381C GET_VERSION";
    case IOCTL_GET_RETADDR:    return "0x3820 GET_RETURN_ADDRESS";
    case IOCTL_GET_TOKEN_BASE: return "0x3824 GET_TOKEN_BASE";
    case IOCTL_AUTH_RESPONSE:  return "0x3828 AUTH_RESPONSE";
    case IOCTL_INTEGRITY:      return "0x382C INTEGRITY_TRANSFORM";
    default:                   return "UNKNOWN";
    }
}

static BOOL EmuNameMatchesBuf(const WCHAR* buf, SIZE_T chars) {
    static const WCHAR needle[] = L"htsysm6321";
    const SIZE_T nlen = 10;
    SIZE_T i, j;
    if (!buf) return FALSE;
    for (i = 0; i + nlen <= chars; i++) {
        for (j = 0; j < nlen; j++) {
            WCHAR c = buf[i + j];
            if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
            if (c != needle[j]) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

static BOOL EmuNameMatches(const WCHAR* s) {
    return s && EmuNameMatchesBuf(s, wcslen(s));
}

static BOOL EmuWideContainsCI(const WCHAR* buf, SIZE_T chars,
                              const WCHAR* needle) {
    SIZE_T i, j, nlen;
    if (!buf || !needle) return FALSE;
    nlen = wcslen(needle);
    if (!nlen || chars < nlen) return FALSE;
    for (i = 0; i + nlen <= chars; i++) {
        for (j = 0; j < nlen; j++) {
            WCHAR a = buf[i + j];
            WCHAR b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

static BOOL EmuWideEndsWithCI(const WCHAR* buf, SIZE_T chars,
                              const WCHAR* suffix) {
    SIZE_T suffixChars;
    if (!buf || !suffix) return FALSE;
    suffixChars = wcslen(suffix);
    if (chars < suffixChars) return FALSE;
    return _wcsnicmp(buf + chars - suffixChars,
                     suffix, suffixChars) == 0;
}

// hacky, but it works.
static BOOL EmuInterestingDiskNameBuf(const WCHAR* buf, SIZE_T chars) {
    return EmuWideContainsCI(buf, chars, L"usrdrv017964") ||
           EmuWideContainsCI(buf, chars, L"htsysm6321") ||
           EmuWideEndsWithCI(buf, chars, L".sys") ||
           EmuWideEndsWithCI(buf, chars, L".cat") ||
           EmuWideEndsWithCI(buf, chars, L".inf");
}

static BOOL EmuInterestingDiskName(const WCHAR* s) {
    return s && EmuInterestingDiskNameBuf(s, wcslen(s));
}

static void EmuLogNativeDiskProbe(const char* api,
                                  POBJECT_ATTRIBUTES attributes,
                                  NTSTATUS status,
                                  void* caller) {
    WCHAR path[512];
    SIZE_T chars;
    if (!g_TraceEnabled || !attributes || !attributes->ObjectName ||
        !attributes->ObjectName->Buffer)
        return;
    chars = attributes->ObjectName->Length / sizeof(WCHAR);
    if (!EmuInterestingDiskNameBuf(attributes->ObjectName->Buffer, chars))
        return;
    if (chars >= ARRAYSIZE(path)) chars = ARRAYSIZE(path) - 1;
    memcpy(path, attributes->ObjectName->Buffer, chars * sizeof(WCHAR));
    path[chars] = L'\0';
    LogMessage("[Trace] disk %s(\"%ls\") -> 0x%08lX",
               api, path, (ULONG)status);
    EmuLogAddress("disk probe caller:", caller);
}

static BOOL EmuIsFakeHandle(HANDLE h) {
    return h == EMU_FAKE_HANDLE_VALUE;
}

// Never reproduce the original driver's unsafe out-of-image reads
static UCHAR EmuDriverByte(LONGLONG off) {
    if (g_SysBytes && off >= 0) {
        ULONGLONG rva = (ULONGLONG)off;
        int i;

        if (rva < g_SysHeadersSize && rva < g_SysBytesSize)
            return g_SysBytes[rva];

        for (i = 0; i < g_SectionCount; i++) {
            if (rva >= g_Sections[i].vaStart && rva < g_Sections[i].vaEnd) {
                ULONGLONG delta = rva - g_Sections[i].vaStart;
                ULONGLONG raw = (ULONGLONG)g_Sections[i].rawStart + delta;
                if (delta < g_Sections[i].rawSize && raw < g_SysBytesSize)
                    return g_SysBytes[raw];
                return 0;
            }
        }

        if (rva < g_SysImageSize)
            return 0;
    }
    {
        ULONG64 x = (ULONG64)off * 0x9E3779B97F4A7C15ULL;
        x ^= x >> 29; x *= 0xBF58476D1CE4E5B9ULL; x ^= x >> 32;
        return (UCHAR)x;
    }
}

static ULONG32 EmuImageDword(LONGLONG rva) {
    return (ULONG32)EmuDriverByte(rva) |
           ((ULONG32)EmuDriverByte(rva + 1) << 8) |
           ((ULONG32)EmuDriverByte(rva + 2) << 16) |
           ((ULONG32)EmuDriverByte(rva + 3) << 24);
}

static ULONG32 EmuG10(int idx, LONG callRetRva, ULONG32 cl) {
    static const signed char deltas[32] = {
        0x16, -0x2E, -0x72, 0x4A, -0x0B, -0x4F, 0x6D, 0x29,
        -0x2C, -0x70, 0x4C, 0x08, -0x4D, 0x6F, 0x2B, -0x19,
        -0x6E, 0x4E, 0x0A, -0x3A, 0x71, 0x2D, -0x17, -0x5B,
        0x50, 0x0C, -0x38, -0x7C, 0x2F, -0x15, -0x59, 0x63
    };
    return (ULONG32)EmuDriverByte(callRetRva + (LONG)deltas[idx]) ^ cl ^
           (ULONG32)(EMU_FAKE_DRIVER_BASE + (ULONG32)callRetRva);
}

static ULONG32 EmuBitNet(ULONG32 x) {
    ULONG32 edi = 0;
    ULONG32 r8  = ((x & 3) << 1) | (x >> 31);
    ULONG32 c   = ((x & 1) << 2) | (x >> 30);
    ULONG32 cl;
    if (r8 - 1 <= 3) edi = 1;
    if (c - 1 <= 3)  edi |= 0x80000000u;
    for (cl = 1; cl < 0x1F; cl++) {
        ULONG32 v = (x >> (cl - 1)) & 7;
        if (v - 1 <= 3) edi |= (1u << cl);
    }
    return edi;
}

static ULONG32 EmuMix30F8(ULONG32 x, int gadgets) {
    ULONG32 edi = EmuBitNet(x);
    if (gadgets) {
        edi ^= EmuG10(16 + (int)(edi & 0xF), 0x3185, edi & 0xFF);
        edi ^= EmuG10(16 + (int)(edi & 0xF), 0x319A, edi & 0xFF);
    }
    return edi;
}

static ULONG32 EmuP3Gadget(int k, ULONG32 input) {
    static const ULONG32 start_xor[16] = {
        0x88322991u, 0u,          0x19D89909u, 0u,
        0x3DB3D670u, 0u,          0xCF5A45E8u, 0u,
        0xF335834Fu, 0u,          0x84DBF2C7u, 0u,
        0xA8B7302Eu, 0u,          0x3A5D9FA6u, 0u
    };
    static const ULONG32 round_xor[16] = {
        0x1A66F780u, 0x633A2F3Cu, 0xAC0D66F8u, 0xF4E09EB4u,
        0xCFE8A45Fu, 0x18BBDC1Bu, 0x618F13D7u, 0xAA624B93u,
        0x856A513Eu, 0xCE3D88FAu, 0x1710C0B6u, 0x5FE3F872u,
        0x3AEBFE1Du, 0x83BF35D9u, 0xCC926D95u, 0x1565A551u
    };
    static const ULONG32 end_xor[16] = {
        0u,          0xF56EFD2Bu, 0u,          0x87156CA3u,
        0u,          0xAAF0AA0Au, 0u,          0x3C971982u,
        0u,          0x607256E9u, 0u,          0xF218C661u,
        0u,          0x15F403C8u, 0u,          0xA79A7340u
    };
    static const LONG sub_ret[16] = {
        0x2546, 0x25B1, 0x2627, 0x2691, 0x2706, 0x2771, 0x27E7, 0x2851,
        0x28C6, 0x2931, 0x29A7, 0x2A11, 0x2A86, 0x2AF1, 0x2B67, 0x2BD1
    };
    ULONG32 v = input ^ start_xor[k];
    int r;
    for (r = 0; r < 5; r++) {
        ULONG32 b = (r == (k & 3)) ? (v ^ round_xor[k]) : v;
        v = EmuG10((int)(b & 0x1F), sub_ret[k], b & 0xFF) ^ b;
    }
    return v ^ end_xor[k];
}

typedef struct _EMU_BUF {
    int          kind;
    LONGLONG     rva;
    ULONG32      abs32; // n > 1 ptr xor) 
    const UCHAR* bytes;
    ULONG32      len;
} EMU_BUF;

static ULONG32 EmuDwordMix(const EMU_BUF* b) {
    ULONG32 n = b->len >> 2;
    ULONG32 init, rol_, ror_, ebx, i;
    if (n == 0) return 0;
    init = ((n >> 10) ^ n) & 0xF;
    rol_ = init; ror_ = init; ebx = n;
    for (i = 0; i < n; i++) {
        ULONG32 d = (b->kind == 0) ? EmuImageDword(b->rva + (LONGLONG)i * 4)
                                   : *(const ULONG32*)(b->bytes + i * 4);
        ebx += _rotl(d, (int)rol_);
        ebx += _rotr(d, (int)ror_);
        rol_ = (rol_ + 1 < 0x17) ? rol_ + 1 : 0;
        ror_ = (ror_ + 1 < 0x1D) ? ror_ + 1 : 0;
    }
    if (n > 1) ebx ^= b->abs32;
    return ebx;
}

static ULONG32 EmuVariant(int v, ULONG32 depth, ULONG32 sel, const EMU_BUF* data, LONG callerRetRva) {
    static const ULONG32 seed_const[4] = { 0xA4443C76u, 0xED177432u, 0x35EAABEEu, 0x7EBDE3AAu };
    static const ULONG32 xor_const[4]  = { 0x5CF6D162u, 0x85C4293Eu, 0x9D8784DAu, 0xC70ADC96u };
    static const LONG chain_ret[4]     = { 0x36FF, 0x386D, 0x39DD, 0x3B4D };
    EMU_BUF win;
    LONG winRva = (callerRetRva & ~3L) - 0x100;
    ULONG32 edi = 0, ebx;
    int i;

    win.kind = 0; win.rva = winRva;
    win.abs32 = (ULONG32)(EMU_FAKE_DRIVER_BASE + (ULONG32)winRva);
    win.bytes = NULL; win.len = 0x200;
    edi ^= EmuDwordMix(&win);
    if (data) edi ^= EmuDwordMix(data);

    if (depth) {
        int idx = (int)((edi ^ sel) & 3);
        edi ^= EmuVariant(idx, depth - 1, edi, NULL, chain_ret[v]);
    }

    ebx = EmuMix30F8(seed_const[v], 1) ^ xor_const[v];
    for (i = 0; i < 3; i++)
        ebx ^= EmuP3Gadget((int)(ebx & 0xF), ebx);
    return ebx ^ edi;
}

static ULONG32 EmuRunTransform(const EMU_BUF* data) {
    ULONG32 pid = GetCurrentProcessId();
    int v = (int)((pid >> 2) & 3);
    return EmuVariant(v, 2, 0, data, 0x3584);
}

static ULONG32 EmuPidToken16Rounds(ULONG32 pid) {
    ULONG32 x = pid; // ^ seed (0)
    int i;
    for (i = 0; i < 16; i++)
        x = EmuMix30F8(x, 0); 
    return x;
}

static ULONG64 EmuCurrentPidToken(void) {
    return (ULONG64)EmuPidToken16Rounds(GetCurrentProcessId());
}

static ULONG32 EmuIntegrityTransform(LONGLONG off, ULONG32 len) {
    EMU_BUF data;
    data.kind  = 0;
    data.rva   = off;
    data.abs32 = (ULONG32)(EMU_FAKE_DRIVER_BASE + off);
    data.bytes = NULL;
    data.len   = len;
    return EmuRunTransform(&data);
}

static ULONG32 EmuAuthExpected(void) {
    ULONG32 token = EmuPidToken16Rounds(GetCurrentProcessId());
    EMU_BUF data;
    data.kind  = 1;
    data.rva   = 0;
    data.abs32 = 0; // unused: n == 1 skips the ptr xor
    data.bytes = (const UCHAR*)&token;
    data.len   = 4;
    return EmuRunTransform(&data);
}

static void EmuLoadSysBytes(void) {
    WCHAR path[MAX_PATH];
    DWORD len;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    len = GetEnvironmentVariableW(
        L"HOLO_EMU_DRIVER_IMAGE", path, ARRAYSIZE(path));
    if (len && len < ARRAYSIZE(path)) {
        hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        len = GetModuleFileNameW(g_hModule, path, ARRAYSIZE(path));
    }
    if (hFile == INVALID_HANDLE_VALUE && len && len < ARRAYSIZE(path)) {
        WCHAR* slash = wcsrchr(path, L'\\');
        if (!slash) slash = wcsrchr(path, L'/');
        if (slash) {
            wcscpy_s(slash + 1,
                     (size_t)(path + ARRAYSIZE(path) - (slash + 1)),
                     L"usrdrv017964.sys");
            hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        len = GetSystemDirectoryW(path, ARRAYSIZE(path));
        if (len && len < ARRAYSIZE(path) - 20) {
            if (path[len - 1] != L'\\') path[len++] = L'\\';
            wcscpy_s(path + len, ARRAYSIZE(path) - len,
                     L"usrdrv017964.sys");
            hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage("[Emu] ERROR: usrdrv017964.sys was not found. Place it "
                   "beside Emulator.dll or set HOLO_EMU_DRIVER_IMAGE.");
        return;
    }
    {
        LARGE_INTEGER sz;
        GetFileSizeEx(hFile, &sz);
        if (sz.QuadPart > 0 && sz.QuadPart < (LONGLONG)(64 * 1024 * 1024)) {
            g_SysBytes = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)sz.QuadPart);
            if (g_SysBytes) {
                DWORD rd = 0;
                if (ReadFile(hFile, g_SysBytes, (DWORD)sz.QuadPart, &rd, NULL)) {
                    g_SysBytesSize = rd;
                    if (rd >= sizeof(IMAGE_DOS_HEADER) && ((PIMAGE_DOS_HEADER)g_SysBytes)->e_magic == IMAGE_DOS_SIGNATURE) {
                        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(g_SysBytes + ((PIMAGE_DOS_HEADER)g_SysBytes)->e_lfanew);
                        if ((ULONG_PTR)nt - (ULONG_PTR)g_SysBytes + sizeof(IMAGE_NT_HEADERS64) <= rd && nt->Signature == IMAGE_NT_SIGNATURE) {
                            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
                            int i, n = nt->FileHeader.NumberOfSections;
                            g_SysImageSize = nt->OptionalHeader.SizeOfImage;
                            g_SysHeadersSize = nt->OptionalHeader.SizeOfHeaders;
                            if (n > 32) n = 32;
                            for (i = 0; i < n; i++) {
                                ULONG32 mappedSize = sec[i].Misc.VirtualSize;
                                if (mappedSize < sec[i].SizeOfRawData)
                                    mappedSize = sec[i].SizeOfRawData;
                                g_Sections[i].vaStart  = sec[i].VirtualAddress;
                                g_Sections[i].vaEnd    = sec[i].VirtualAddress + mappedSize;
                                g_Sections[i].rawStart = sec[i].PointerToRawData;
                                g_Sections[i].rawSize  = sec[i].SizeOfRawData;
                            }
                            g_SectionCount = n;
                        }
                    }
                    LogMessage("[Emu] loaded %llu bytes from \"%ls\" for "
                               "0x382C (%d sections, image size 0x%lX)",
                               (unsigned long long)rd, path,
                               g_SectionCount, g_SysImageSize);
                } else {
                    HeapFree(GetProcessHeap(), 0, g_SysBytes);
                    g_SysBytes = NULL;
                }
            }
        }
    }
    CloseHandle(hFile);
}

static void EmuResetRecord(void) {
    g_State.auth_state         = 0;
    g_State.enabled            = 0;
    g_State.active             = 0;
    ZeroMemory(g_State.trusted_pid, sizeof(g_State.trusted_pid));
    ZeroMemory(g_State.parent_pid, sizeof(g_State.parent_pid));
    g_State.svchost_parent_pid = 0;
    ZeroMemory(g_State.telemetry, sizeof(g_State.telemetry));
}

static HANDLE EmuOpenDevice(void) {
    EnterCriticalSection(&g_Lock);
    if (g_State.handle_open) {
        LeaveCriticalSection(&g_Lock);
        LogMessage("[Emu] CREATE: second open from same PID rejected");
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    EmuResetRecord();
    g_State.handle_open = TRUE;
    LeaveCriticalSection(&g_Lock);
    LogMessage("[Emu] CREATE: device opened (fake handle, state=0)");
    return EMU_FAKE_HANDLE_VALUE;
}

static void EmuCloseDevice(void) {
    EnterCriticalSection(&g_Lock);
    g_State.handle_open = FALSE;
    EmuResetRecord();
    LeaveCriticalSection(&g_Lock);
    LogMessage("[Emu] CLEANUP: record removed");
}

static NTSTATUS EmuWriteOut(PVOID outBuf, ULONG outSize, ULONG need, const void* src, ULONG_PTR* info) {
    if (outSize < need || !outBuf) return STATUS_BUFFER_TOO_SMALL;
    memcpy(outBuf, src, need);
    *info = need;
    return STATUS_SUCCESS;
}

static NTSTATUS EmuCheckState(ULONG code) {
    UINT16 s = g_State.auth_state;
    if (s == 2) return STATUS_ACCESS_DENIED;
    if (s == 0) {
        if (code == IOCTL_GET_VERSION || code == IOCTL_GET_TOKEN_BASE || code == IOCTL_AUTH_RESPONSE)
            return STATUS_SUCCESS;
        return STATUS_ACCESS_DENIED;
    }
    if (code == IOCTL_AUTH_RESPONSE) return STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}

static NTSTATUS EmuDispatch(ULONG code, PVOID inBuf, ULONG inSize, PVOID outBuf, ULONG outSize, ULONG_PTR* info) {
    NTSTATUS st;
    *info = 0;

    EnterCriticalSection(&g_Lock);
    st = EmuCheckState(code);
    if (!NT_SUCCESS(st)) {
        UINT16 curState = g_State.auth_state;
        LeaveCriticalSection(&g_Lock);
        LogMessage("[Emu] IOCTL %-28s REJECTED by state gate (state=%u)", EmuIoctlName(code), curState);
        return st;
    }

    switch (code) {
    case IOCTL_GET_VERSION: {
        ULONG32 v = EMU_PROTOCOL_VERSION;
        st = EmuWriteOut(outBuf, outSize, 4, &v, info);
        break;
    }
    case IOCTL_GET_TOKEN_BASE: {
        struct { ULONG64 token; ULONG64 base; } r;
        r.token = EmuCurrentPidToken();
        r.base  = EMU_FAKE_DRIVER_BASE;
        st = EmuWriteOut(outBuf, outSize, 0x10, &r, info);
        if (NT_SUCCESS(st))
            LogMessage("[Emu]   token=0x%016llX base=0x%016llX", r.token, r.base);
        break;
    }
    case IOCTL_AUTH_RESPONSE: {
        ULONG32 response = 0;
        ULONG32 expected;
        if (inSize < 4 || !inBuf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        response = *(ULONG32*)inBuf;
        /* Log the expected response, but accept while compatibility is tested. */
        expected = EmuAuthExpected();
        g_State.auth_state = 1;
        LogMessage("[Emu]   auth response=0x%08lX expected=0x%08lX %s (state 0->1)",
                   response, expected, (response == expected) ? "MATCH" : "MISMATCH");
        st = STATUS_SUCCESS;
        break;
    }
    case IOCTL_REG_PATH: {
        if (inSize < 0x208 || !inBuf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        memcpy(g_State.global_path, inBuf, 0x208);
        g_State.global_path[259] = L'\0';
        g_State.enabled = 1;
        g_State.active  = 1;
        LogMessage("[Emu]   registered path \"%ls\", enabled=1 active=1", g_State.global_path);
        st = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DISABLE_ENF:
        g_State.enabled = 0;
        st = STATUS_SUCCESS;
        break;
    case IOCTL_ENABLE_ENF:
        g_State.enabled = 1;
        st = STATUS_SUCCESS;
        break;
    case IOCTL_SET_TRUSTED5:
        if (inSize < 0x14 || !inBuf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        memcpy(g_State.trusted_pid, inBuf, 0x14);
        LogMessage("[Emu]   trusted pids: %lu %lu %lu %lu %lu",
                   g_State.trusted_pid[0], g_State.trusted_pid[1], g_State.trusted_pid[2],
                   g_State.trusted_pid[3], g_State.trusted_pid[4]);
        st = STATUS_SUCCESS;
        break;
    case IOCTL_SET_PARENTS3:
        if (inSize < 0x0C || !inBuf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        memcpy(g_State.parent_pid, inBuf, 0x0C);
        st = STATUS_SUCCESS;
        break;
    case IOCTL_SET_SVC_PARENT:
        if (inSize < 4 || !inBuf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        g_State.svchost_parent_pid = *(ULONG32*)inBuf;
        st = STATUS_SUCCESS;
        break;
    case IOCTL_GET_TELEMETRY:
        st = EmuWriteOut(outBuf, outSize, 0x30, g_State.telemetry, info);
        ZeroMemory(g_State.telemetry, sizeof(g_State.telemetry));
        break;
    case IOCTL_GET_RETADDR: {
        ULONG64 addr = EMU_FAKE_RETURN_ADDR;
        st = EmuWriteOut(outBuf, outSize, 8, &addr, info);
        break;
    }
    case IOCTL_INTEGRITY: {
        LONG   offset;
        ULONG  length;
        ULONG  end;
        ULONG32 result;
        if (inSize < 8 || !inBuf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        offset = *(LONG*)inBuf;
        length = *(ULONG*)((PUCHAR)inBuf + 4);

        end = (ULONG)offset + length;
        if (end > EMU_DRIVER_IMAGE_LIMIT) { st = STATUS_INVALID_PARAMETER; break; }
        if ((ULONG)offset < EMU_DRIVER_OOB_BOUNDARY && end >= EMU_DRIVER_OOB_BOUNDARY) { st = STATUS_INVALID_PARAMETER; break; }

        if (length > EMU_MAX_TRANSFORM_LEN) {
            LogMessage("[Emu]   0x382C length 0x%lX exceeds emulation cap; clamping (deviation)", length);
            length = EMU_MAX_TRANSFORM_LEN;
        }
        result = EmuIntegrityTransform((LONGLONG)offset, length);
        LogMessage("[Emu]   0x382C request offset=0x%08lX (%ld) "
                   "length=0x%lX -> 0x%08lX%s",
                   (ULONG)offset, offset, length, result,
                   (offset < 0) ? " (OOB case)" : "");
        st = EmuWriteOut(outBuf, outSize, 4, &result, info);
        break;
    }
    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    LeaveCriticalSection(&g_Lock);

    if (code != IOCTL_GET_TELEMETRY || g_TraceEnabled) {
        LogMessage("[Emu] IOCTL %-28s in=%lu out=%lu -> 0x%08lX "
                   "(info=%llu)",
                   EmuIoctlName(code), inSize, outSize, (ULONG)st,
                   (unsigned long long)*info);
    }
    return st;
}

static DWORD EmuStatusToWin32(NTSTATUS st) {
    switch (st) {
    case STATUS_INVALID_PARAMETER:      return ERROR_INVALID_PARAMETER;
    case STATUS_ACCESS_DENIED:          return ERROR_ACCESS_DENIED;
    case STATUS_BUFFER_TOO_SMALL:       return ERROR_INSUFFICIENT_BUFFER;
    case STATUS_INVALID_DEVICE_REQUEST: return ERROR_INVALID_FUNCTION;
    default:                            return ERROR_GEN_FAILURE;
    }
}

static HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE result;
    DWORD error;
    void* caller = _ReturnAddress();
    if (EmuNameMatches(lpFileName)) {
        LogMessage("[Emu] CreateFileW(\"%ls\") intercepted", lpFileName);
        return EmuOpenDevice();
    }
    result = OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                                 lpSecurityAttributes, dwCreationDisposition,
                                 dwFlagsAndAttributes, hTemplateFile);
    error = GetLastError();
    if (g_TraceEnabled && EmuInterestingDiskName(lpFileName)) {
        LogMessage("[Trace] disk CreateFileW(\"%ls\", access=0x%lX) "
                   "-> %p error=%lu",
                   lpFileName, dwDesiredAccess, result, error);
        EmuLogAddress("disk probe caller:", caller);
    }
    SetLastError(error);
    return result;
}

static DWORD WINAPI HookedGetFileAttributesW(LPCWSTR lpFileName) {
    void* caller = _ReturnAddress();
    DWORD result = OriginalGetFileAttributesW(lpFileName);
    DWORD error = GetLastError();
    if (g_TraceEnabled && EmuInterestingDiskName(lpFileName)) {
        LogMessage("[Trace] disk GetFileAttributesW(\"%ls\") "
                   "-> 0x%08lX error=%lu",
                   lpFileName, result, error);
        EmuLogAddress("disk probe caller:", caller);
    }
    SetLastError(error);
    return result;
}

static BOOL WINAPI HookedGetFileAttributesExW(
    LPCWSTR lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation) {
    void* caller = _ReturnAddress();
    BOOL result = OriginalGetFileAttributesExW(
        lpFileName, fInfoLevelId, lpFileInformation);
    DWORD error = GetLastError();
    if (g_TraceEnabled && EmuInterestingDiskName(lpFileName)) {
        LogMessage("[Trace] disk GetFileAttributesExW(\"%ls\", level=%lu) "
                   "-> %d error=%lu",
                   lpFileName, (ULONG)fInfoLevelId, result, error);
        EmuLogAddress("disk probe caller:", caller);
    }
    SetLastError(error);
    return result;
}

static DWORD WINAPI HookedQueryDosDeviceW(
    LPCWSTR lpDeviceName, LPWSTR lpTargetPath, DWORD ucchMax) {
    static const WCHAR target[] = L"\\Device\\Htsysm6321";
    void* caller = _ReturnAddress();
    if (EmuNameMatches(lpDeviceName)) {
        DWORD required = (DWORD)ARRAYSIZE(target) + 1; 
        LogMessage("[Emu] QueryDosDeviceW(\"%ls\") -> emulated link",
                   lpDeviceName);
        if (g_TraceEnabled)
            EmuLogAddress("device probe caller:", caller);
        if (!lpTargetPath || ucchMax < required) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        memcpy(lpTargetPath, target, sizeof(target));
        lpTargetPath[ARRAYSIZE(target)] = L'\0';
        return (DWORD)ARRAYSIZE(target);
    }
    return OriginalQueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax);
}

static NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    NTSTATUS st;
    void* caller = _ReturnAddress();
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        EmuNameMatchesBuf(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR))) {
        HANDLE h = EmuOpenDevice();
        if (h == INVALID_HANDLE_VALUE) {
            IoStatusBlock->Status = STATUS_ACCESS_DENIED;
            IoStatusBlock->Information = 0;
            return STATUS_ACCESS_DENIED;
        }
        *FileHandle = h;
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 1; 
        return STATUS_SUCCESS;
    }
    st = OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                              IoStatusBlock, AllocationSize, FileAttributes,
                              ShareAccess, CreateDisposition, CreateOptions,
                              EaBuffer, EaLength);
    EmuLogNativeDiskProbe("NtCreateFile", ObjectAttributes, st, caller);
    return st;
}

static NTSTATUS NTAPI HookedNtQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation) {
    void* caller = _ReturnAddress();
    NTSTATUS st = OriginalNtQueryAttributesFile(
        ObjectAttributes, FileInformation);
    EmuLogNativeDiskProbe("NtQueryAttributesFile", ObjectAttributes,
                          st, caller);
    return st;
}

static NTSTATUS NTAPI HookedNtQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes, PVOID FileInformation) {
    void* caller = _ReturnAddress();
    NTSTATUS st = OriginalNtQueryFullAttributesFile(
        ObjectAttributes, FileInformation);
    EmuLogNativeDiskProbe("NtQueryFullAttributesFile", ObjectAttributes,
                          st, caller);
    return st;
}

static BOOL WINAPI HookedDeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
    if (EmuIsFakeHandle(hDevice)) {
        ULONG_PTR info = 0;
        if (dwIoControlCode == IOCTL_INTEGRITY)
            EmuLogAddress("0x382C Win32 caller:", _ReturnAddress());
        NTSTATUS st = EmuDispatch(dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, &info);
        if (NT_SUCCESS(st)) {
            if (lpBytesReturned) *lpBytesReturned = (DWORD)info;
            return TRUE;
        }
        SetLastError(EmuStatusToWin32(st));
        return FALSE;
    }
    return OriginalDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}

static NTSTATUS NTAPI HookedNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    if (EmuIsFakeHandle(FileHandle)) {
        ULONG_PTR info = 0;
        if (IoControlCode == IOCTL_INTEGRITY)
            EmuLogAddress("0x382C native caller:", _ReturnAddress());
        NTSTATUS st = EmuDispatch(IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, &info);
        IoStatusBlock->Status = st;
        IoStatusBlock->Information = NT_SUCCESS(st) ? info : 0;
        return st;
    }
    return OriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

static void EmuUntrackKey(HANDLE handle);

static BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    if (EmuIsFakeHandle(hObject)) {
        EmuCloseDevice();
        return TRUE;
    }
    if (hObject == EMU_FAKE_SYMLINK_HANDLE) return TRUE;
    return OriginalCloseHandle(hObject);
}

static NTSTATUS NTAPI HookedNtClose(HANDLE Handle) {
    if (EmuIsFakeHandle(Handle)) {
        EmuCloseDevice();
        return STATUS_SUCCESS;
    }
    if (Handle == EMU_FAKE_SYMLINK_HANDLE) return STATUS_SUCCESS;
    EmuUntrackKey(Handle);
    return OriginalNtClose(Handle);
}

#define EMU_FAKE_SC_HANDLE ((SC_HANDLE)(ULONG_PTR)0x1757CA11)
static BOOL g_SvcRunning = FALSE;

static BOOL EmuSvcNameMatchesW(const WCHAR* s) {
    static const WCHAR needle[] = L"usrdrv017964";
    const SIZE_T nlen = 12;
    SIZE_T i, j, chars;
    if (!s) return FALSE;
    chars = wcslen(s);
    for (i = 0; i + nlen <= chars; i++) {
        for (j = 0; j < nlen; j++) {
            WCHAR c = s[i + j];
            if (c >= L'A' && c <= L'Z') c = (WCHAR)(c + 32);
            if (c != needle[j]) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

static BOOL EmuSvcNameMatchesA(const char* s) {
    static const char needle[] = "usrdrv017964";
    const SIZE_T nlen = 12;
    SIZE_T i, j, chars;
    if (!s) return FALSE;
    chars = strlen(s);
    for (i = 0; i + nlen <= chars; i++) {
        for (j = 0; j < nlen; j++) {
            char c = s[i + j];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            if (c != needle[j]) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

static BOOL EmuIsFakeScHandle(SC_HANDLE h) {
    return h == EMU_FAKE_SC_HANDLE;
}

static void EmuFillServiceStatus(LPSERVICE_STATUS ss) {
    ZeroMemory(ss, sizeof(*ss));
    ss->dwServiceType        = SERVICE_KERNEL_DRIVER;
    ss->dwCurrentState       = g_SvcRunning ? SERVICE_RUNNING : SERVICE_STOPPED;
    ss->dwControlsAccepted   = 0;
    ss->dwWin32ExitCode      = 0;
    ss->dwCheckPoint         = 0;
    ss->dwWaitHint           = 0;
}

static SC_HANDLE WINAPI HookedOpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess) {
    if (EmuSvcNameMatchesW(lpServiceName)) {
        LogMessage("[Emu] OpenServiceW(\"%ls\") -> fake handle", lpServiceName);
        return EMU_FAKE_SC_HANDLE;
    }
    return OriginalOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
}

static SC_HANDLE WINAPI HookedOpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess) {
    if (EmuSvcNameMatchesA(lpServiceName)) {
        LogMessage("[Emu] OpenServiceA(\"%s\") -> fake handle", lpServiceName);
        return EMU_FAKE_SC_HANDLE;
    }
    return OriginalOpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
}

static SC_HANDLE WINAPI HookedCreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {
    if (EmuSvcNameMatchesW(lpServiceName) || EmuSvcNameMatchesW(lpBinaryPathName)) {
        LogMessage("[Emu] CreateServiceW(\"%ls\", bin=\"%ls\") -> fake handle (no real install)",
                   lpServiceName ? lpServiceName : L"?", lpBinaryPathName ? lpBinaryPathName : L"?");
        g_SvcRunning = FALSE;
        return EMU_FAKE_SC_HANDLE;
    }
    return OriginalCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}

static SC_HANDLE WINAPI HookedCreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword) {
    if (EmuSvcNameMatchesA(lpServiceName) || EmuSvcNameMatchesA(lpBinaryPathName)) {
        LogMessage("[Emu] CreateServiceA(\"%s\") -> fake handle (no real install)", lpServiceName ? lpServiceName : "?");
        g_SvcRunning = FALSE;
        return EMU_FAKE_SC_HANDLE;
    }
    return OriginalCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
}

static BOOL WINAPI HookedStartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) {
    if (EmuIsFakeScHandle(hService)) {
        LogMessage("[Emu] StartServiceW(fake) -> SUCCESS (driver not actually loaded)");
        g_SvcRunning = TRUE;
        return TRUE;
    }
    return OriginalStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
}

static BOOL WINAPI HookedStartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors) {
    if (EmuIsFakeScHandle(hService)) {
        LogMessage("[Emu] StartServiceA(fake) -> SUCCESS (driver not actually loaded)");
        g_SvcRunning = TRUE;
        return TRUE;
    }
    return OriginalStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
}

static BOOL WINAPI HookedQueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus) {
    if (EmuIsFakeScHandle(hService)) {
        EmuFillServiceStatus(lpServiceStatus);
        if (g_TraceEnabled)
            LogMessage("[Trace] service QueryServiceStatus(fake) -> %s",
                       g_SvcRunning ? "RUNNING" : "STOPPED");
        return TRUE;
    }
    return OriginalQueryServiceStatus(hService, lpServiceStatus);
}

static BOOL WINAPI HookedQueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded) {
    if (EmuIsFakeScHandle(hService)) {
        SERVICE_STATUS_PROCESS ssp;
        if (InfoLevel != SC_STATUS_PROCESS_INFO) { SetLastError(ERROR_INVALID_LEVEL); return FALSE; }
        if (cbBufSize < sizeof(ssp)) {
            if (pcbBytesNeeded) *pcbBytesNeeded = sizeof(ssp);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        ZeroMemory(&ssp, sizeof(ssp));
        ssp.dwServiceType  = SERVICE_KERNEL_DRIVER;
        ssp.dwCurrentState = g_SvcRunning ? SERVICE_RUNNING : SERVICE_STOPPED;
        memcpy(lpBuffer, &ssp, sizeof(ssp));
        if (pcbBytesNeeded) *pcbBytesNeeded = sizeof(ssp);
        if (g_TraceEnabled)
            LogMessage("[Trace] service QueryServiceStatusEx(fake) -> %s",
                       g_SvcRunning ? "RUNNING" : "STOPPED");
        return TRUE;
    }
    return OriginalQueryServiceStatusEx(hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);
}

static BOOL WINAPI HookedQueryServiceConfigW(
    SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW config,
    DWORD cbBufSize, LPDWORD bytesNeeded) {
    static const WCHAR binary[] =
        L"C:\\Windows\\System32\\usrdrv017964.sys";
    static const WCHAR empty[] = L"";
    static const WCHAR dependencies[] = { L'\0', L'\0' };
    static const WCHAR display[] = L"usrdrv017964";
    DWORD required = sizeof(*config) + sizeof(binary) + sizeof(empty) +
                     sizeof(dependencies) + sizeof(empty) + sizeof(display);
    BYTE* cursor;
    if (!EmuIsFakeScHandle(hService))
        return OriginalQueryServiceConfigW(
            hService, config, cbBufSize, bytesNeeded);
    if (bytesNeeded) *bytesNeeded = required;
    if (g_TraceEnabled)
        LogMessage("[Trace] service QueryServiceConfigW(fake, bytes=%lu) "
                   "requires=%lu", cbBufSize, required);
    if (!config || cbBufSize < required) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    ZeroMemory(config, required);
    config->dwServiceType = SERVICE_KERNEL_DRIVER;
    config->dwStartType = SERVICE_DEMAND_START;
    config->dwErrorControl = SERVICE_ERROR_NORMAL;
    cursor = (BYTE*)config + sizeof(*config);
#define EMU_PACK_CONFIG_W(field, value) \
    do { \
        config->field = (LPWSTR)cursor; \
        memcpy(cursor, value, sizeof(value)); \
        cursor += sizeof(value); \
    } while (0)
    EMU_PACK_CONFIG_W(lpBinaryPathName, binary);
    EMU_PACK_CONFIG_W(lpLoadOrderGroup, empty);
    EMU_PACK_CONFIG_W(lpDependencies, dependencies);
    EMU_PACK_CONFIG_W(lpServiceStartName, empty);
    EMU_PACK_CONFIG_W(lpDisplayName, display);
#undef EMU_PACK_CONFIG_W
    return TRUE;
}

static BOOL WINAPI HookedQueryServiceConfigA(
    SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA config,
    DWORD cbBufSize, LPDWORD bytesNeeded) {
    static const char binary[] =
        "C:\\Windows\\System32\\usrdrv017964.sys";
    static const char empty[] = "";
    static const char dependencies[] = { '\0', '\0' };
    static const char display[] = "usrdrv017964";
    DWORD required = sizeof(*config) + sizeof(binary) + sizeof(empty) +
                     sizeof(dependencies) + sizeof(empty) + sizeof(display);
    BYTE* cursor;
    if (!EmuIsFakeScHandle(hService))
        return OriginalQueryServiceConfigA(
            hService, config, cbBufSize, bytesNeeded);
    if (bytesNeeded) *bytesNeeded = required;
    if (g_TraceEnabled)
        LogMessage("[Trace] service QueryServiceConfigA(fake, bytes=%lu) "
                   "requires=%lu", cbBufSize, required);
    if (!config || cbBufSize < required) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    ZeroMemory(config, required);
    config->dwServiceType = SERVICE_KERNEL_DRIVER;
    config->dwStartType = SERVICE_DEMAND_START;
    config->dwErrorControl = SERVICE_ERROR_NORMAL;
    cursor = (BYTE*)config + sizeof(*config);
#define EMU_PACK_CONFIG_A(field, value) \
    do { \
        config->field = (LPSTR)cursor; \
        memcpy(cursor, value, sizeof(value)); \
        cursor += sizeof(value); \
    } while (0)
    EMU_PACK_CONFIG_A(lpBinaryPathName, binary);
    EMU_PACK_CONFIG_A(lpLoadOrderGroup, empty);
    EMU_PACK_CONFIG_A(lpDependencies, dependencies);
    EMU_PACK_CONFIG_A(lpServiceStartName, empty);
    EMU_PACK_CONFIG_A(lpDisplayName, display);
#undef EMU_PACK_CONFIG_A
    return TRUE;
}

static BOOL WINAPI HookedEnumServicesStatusExW(
    SC_HANDLE manager, SC_ENUM_TYPE infoLevel, DWORD serviceType,
    DWORD serviceState, LPBYTE services, DWORD cbBufSize,
    LPDWORD bytesNeeded, LPDWORD servicesReturned,
    LPDWORD resumeHandle, LPCWSTR groupName) {
    DWORD i, count = 0;
    BOOL result = OriginalEnumServicesStatusExW(
        manager, infoLevel, serviceType, serviceState, services, cbBufSize,
        bytesNeeded, servicesReturned, resumeHandle, groupName);
    DWORD error = GetLastError();
    if (servicesReturned) count = *servicesReturned;
    if (infoLevel == SC_ENUM_PROCESS_INFO && services) {
        LPENUM_SERVICE_STATUS_PROCESSW entries =
            (LPENUM_SERVICE_STATUS_PROCESSW)services;
        for (i = 0; i < count; i++) {
            if (EmuSvcNameMatchesW(entries[i].lpServiceName)) {
                entries[i].ServiceStatusProcess.dwServiceType =
                    SERVICE_KERNEL_DRIVER;
                entries[i].ServiceStatusProcess.dwCurrentState =
                    SERVICE_RUNNING;
                entries[i].ServiceStatusProcess.dwWin32ExitCode = 0;
                if (g_TraceEnabled)
                    LogMessage("[Trace] service EnumServicesStatusExW found "
                               "usrdrv017964; patched state to RUNNING");
            }
        }
    }
    if (g_TraceEnabled)
        LogMessage("[Trace] service EnumServicesStatusExW(type=0x%lX, "
                   "state=0x%lX, returned=%lu) -> %d error=%lu",
                   serviceType, serviceState, count, result, error);
    SetLastError(error);
    return result;
}

static BOOL WINAPI HookedEnumServicesStatusExA(
    SC_HANDLE manager, SC_ENUM_TYPE infoLevel, DWORD serviceType,
    DWORD serviceState, LPBYTE services, DWORD cbBufSize,
    LPDWORD bytesNeeded, LPDWORD servicesReturned,
    LPDWORD resumeHandle, LPCSTR groupName) {
    DWORD i, count = 0;
    BOOL result = OriginalEnumServicesStatusExA(
        manager, infoLevel, serviceType, serviceState, services, cbBufSize,
        bytesNeeded, servicesReturned, resumeHandle, groupName);
    DWORD error = GetLastError();
    if (servicesReturned) count = *servicesReturned;
    if (infoLevel == SC_ENUM_PROCESS_INFO && services) {
        LPENUM_SERVICE_STATUS_PROCESSA entries =
            (LPENUM_SERVICE_STATUS_PROCESSA)services;
        for (i = 0; i < count; i++) {
            if (EmuSvcNameMatchesA(entries[i].lpServiceName)) {
                entries[i].ServiceStatusProcess.dwServiceType =
                    SERVICE_KERNEL_DRIVER;
                entries[i].ServiceStatusProcess.dwCurrentState =
                    SERVICE_RUNNING;
                entries[i].ServiceStatusProcess.dwWin32ExitCode = 0;
                if (g_TraceEnabled)
                    LogMessage("[Trace] service EnumServicesStatusExA found "
                               "usrdrv017964; patched state to RUNNING");
            }
        }
    }
    if (g_TraceEnabled)
        LogMessage("[Trace] service EnumServicesStatusExA(type=0x%lX, "
                   "state=0x%lX, returned=%lu) -> %d error=%lu",
                   serviceType, serviceState, count, result, error);
    SetLastError(error);
    return result;
}

static BOOL WINAPI HookedControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) {
    if (EmuIsFakeScHandle(hService)) {
        if (dwControl == SERVICE_CONTROL_STOP) {
            g_SvcRunning = FALSE;
            LogMessage("[Emu] ControlService(fake, STOP) -> service \"stopped\"");
        }
        if (lpServiceStatus) EmuFillServiceStatus(lpServiceStatus);
        return TRUE;
    }
    return OriginalControlService(hService, dwControl, lpServiceStatus);
}

static BOOL WINAPI HookedDeleteService(SC_HANDLE hService) {
    if (EmuIsFakeScHandle(hService)) {
        LogMessage("[Emu] DeleteService(fake) -> SUCCESS (nothing real deleted)");
        g_SvcRunning = FALSE;
        return TRUE;
    }
    return OriginalDeleteService(hService);
}

static BOOL WINAPI HookedCloseServiceHandle(SC_HANDLE hSCObject) {
    if (EmuIsFakeScHandle(hSCObject)) return TRUE;
    return OriginalCloseServiceHandle(hSCObject);
}

static BOOL WINAPI HookedChangeServiceConfigW(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName) {
    if (EmuIsFakeScHandle(hService)) {
        LogMessage("[Emu] ChangeServiceConfigW(fake, start=%lu) -> SUCCESS", dwStartType);
        return TRUE;
    }
    return OriginalChangeServiceConfigW(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
}

static BOOL WINAPI HookedChangeServiceConfigA(SC_HANDLE hService, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword, LPCSTR lpDisplayName) {
    if (EmuIsFakeScHandle(hService)) {
        LogMessage("[Emu] ChangeServiceConfigA(fake, start=%lu) -> SUCCESS", dwStartType);
        return TRUE;
    }
    return OriginalChangeServiceConfigA(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName);
}

static NTSTATUS NTAPI HookedNtLoadDriver(PUNICODE_STRING DriverServiceName) {
    if (DriverServiceName && EmuSvcNameMatchesW(DriverServiceName->Buffer)) {
        LogMessage("[Emu] NtLoadDriver(\"%ls\") -> faked SUCCESS (driver not loaded)", DriverServiceName->Buffer);
        g_SvcRunning = TRUE;
        return STATUS_SUCCESS;
    }
    return OriginalNtLoadDriver(DriverServiceName);
}

static void EmuLogExitSite(const char* api, unsigned code, void* retaddr) {
    HMODULE hm = NULL;
    if (retaddr && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      (LPCSTR)retaddr, &hm) && hm) {
        char modname[MAX_PATH];
        GetModuleFileNameA(hm, modname, MAX_PATH);
        char* base = strrchr(modname, '\\');
        LogMessage("[Emu] %s(code=0x%X) from %s+0x%llX", api, code,
                   base ? base + 1 : modname, (unsigned long long)((ULONG_PTR)retaddr - (ULONG_PTR)hm));
    } else {
        LogMessage("[Emu] %s(code=0x%X) from unbacked address %p", api, code, retaddr);
    }

    /* Record one full exit stack per process. */
    if (InterlockedCompareExchange(&g_ExitStackLogged, 1, 0) == 0) {
        PVOID frames[16];
        USHORT count = CaptureStackBackTrace(1, 16, frames, NULL);
        USHORT i;
        LogMessage("[Emu] first process-exit stack (%u frames):", count);
        for (i = 0; i < count; i++) {
            HMODULE frameModule = NULL;
            if (frames[i] &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)frames[i], &frameModule) &&
                frameModule) {
                char modulePath[MAX_PATH];
                char* moduleName;
                GetModuleFileNameA(frameModule, modulePath, MAX_PATH);
                moduleName = strrchr(modulePath, '\\');
                LogMessage("[Emu]   #%u %s+0x%llX", i,
                           moduleName ? moduleName + 1 : modulePath,
                           (unsigned long long)((ULONG_PTR)frames[i] -
                                                (ULONG_PTR)frameModule));
            } else {
                LogMessage("[Emu]   #%u %p (unbacked)", i, frames[i]);
            }
        }
    }
}

static void NTAPI HookedRtlExitUserProcess(NTSTATUS status) {
    EmuLogExitSite("RtlExitUserProcess", (unsigned)status, _ReturnAddress());
    OriginalRtlExitUserProcess(status);
}

static BOOL WINAPI HookedTerminateProcess(HANDLE hProcess, UINT uExitCode) {
    DWORD pid = hProcess ? GetProcessId(hProcess) : GetCurrentProcessId();
    LogMessage("[Emu] TerminateProcess(pid=%lu, code=0x%X)", pid, uExitCode);
    EmuLogExitSite("TerminateProcess", uExitCode, _ReturnAddress());
    return OriginalTerminateProcess(hProcess, uExitCode);
}

NTSTATUS NTAPI EmuHookedNtTerminateProcessC(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus) {
    DWORD pid = 0;
    if (!ProcessHandle || ProcessHandle == (HANDLE)-1) pid = GetCurrentProcessId();
    else pid = GetProcessId(ProcessHandle);
    LogMessage("[Emu] NtTerminateProcess(pid=%lu, status=0x%lX)", pid, (ULONG)ExitStatus);
    EmuLogExitSite("NtTerminateProcess", (unsigned)ExitStatus, _ReturnAddress());
    return OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
}

NTSTATUS NTAPI EmuHookedNtRaiseExceptionC(
    PEXCEPTION_RECORD exceptionRecord,
    PCONTEXT contextRecord,
    BOOLEAN firstChance) {
    if (!firstChance && exceptionRecord && contextRecord) {
        EXCEPTION_POINTERS pointers;
        LogMessage("[Emu] Wine second-chance exception "
                   "code=0x%08lX address=%p",
                   (ULONG)exceptionRecord->ExceptionCode,
                   exceptionRecord->ExceptionAddress);
        pointers.ExceptionRecord = exceptionRecord;
        pointers.ContextRecord = contextRecord;
        EmuCrashObserver(&pointers);
    }
    return OriginalNtRaiseException(
        exceptionRecord, contextRecord, firstChance);
}

static NTSTATUS NTAPI HookedNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    NTSTATUS st;
    void* caller = _ReturnAddress();
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        EmuNameMatchesBuf(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR))) {
        HANDLE h = EmuOpenDevice();
        if (h == INVALID_HANDLE_VALUE) {
            IoStatusBlock->Status = STATUS_ACCESS_DENIED;
            IoStatusBlock->Information = 0;
            return STATUS_ACCESS_DENIED;
        }
        LogMessage("[Emu] NtOpenFile(device) intercepted -> fake handle");
        *FileHandle = h;
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 1; /* FILE_OPENED */
        return STATUS_SUCCESS;
    }
    st = OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                            IoStatusBlock, ShareAccess, OpenOptions);
    EmuLogNativeDiskProbe("NtOpenFile", ObjectAttributes, st, caller);
    return st;
}

//real kymera technology.
#define EMU_SYSMOD_ENTRY_SIZE 296
static ULONG64 g_QsiClassLogged[8];
typedef struct _EMU_SYSTEM_PROCESS_INFORMATION_PREFIX {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
} EMU_SYSTEM_PROCESS_INFORMATION_PREFIX;

static void EmuTraceSystemProcessList(
    PVOID buffer,
    ULONG bufferLength,
    ULONG returnedLength) {
    BYTE* base = (BYTE*)buffer;
    ULONG limit = returnedLength &&
                  returnedLength <= bufferLength
                    ? returnedLength
                    : bufferLength;
    ULONG offset = 0;
    ULONG count = 0;
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentParent = 0;
    BOOL currentFound = FALSE;

    if (!g_IsWine || !g_TraceEnabled || !base ||
        limit < sizeof(EMU_SYSTEM_PROCESS_INFORMATION_PREFIX))
        return;

    for (;;) {
        EMU_SYSTEM_PROCESS_INFORMATION_PREFIX* entry;
        ULONG remaining;
        DWORD pid;
        DWORD parentPid;
        WCHAR image[96];
        ULONG imageChars = 0;
        ULONG next;

        if (offset >= limit)
            break;
        remaining = limit - offset;
        if (remaining < sizeof(*entry))
            break;

        entry = (EMU_SYSTEM_PROCESS_INFORMATION_PREFIX*)(base + offset);
        pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
        parentPid = (DWORD)(ULONG_PTR)entry->InheritedFromUniqueProcessId;

        image[0] = L'\0';
        if (entry->ImageName.Buffer && entry->ImageName.Length) {
            ULONG_PTR imageStart = (ULONG_PTR)entry->ImageName.Buffer;
            ULONG_PTR listStart = (ULONG_PTR)base;
            ULONG_PTR listEnd = listStart + limit;
            ULONG bytes = entry->ImageName.Length;

            if (imageStart >= listStart &&
                imageStart < listEnd &&
                bytes <= listEnd - imageStart) {
                imageChars = bytes / sizeof(WCHAR);
                if (imageChars >= ARRAYSIZE(image))
                    imageChars = ARRAYSIZE(image) - 1;
                memcpy(image, entry->ImageName.Buffer,
                       imageChars * sizeof(WCHAR));
                image[imageChars] = L'\0';
            }
        }

        LogMessage("[Trace] Wine process[%lu]: pid=%lu ppid=%lu "
                   "threads=%lu image=\"%ls\"",
                   count, pid, parentPid, entry->NumberOfThreads,
                   imageChars ? image : L"<unnamed>");

        if (pid == currentPid) {
            currentFound = TRUE;
            currentParent = parentPid;
        }
        count++;

        next = entry->NextEntryOffset;
        if (!next)
            break;
        if (next < sizeof(*entry) || next > remaining)
            break;
        offset += next;
        if (count >= 4096)
            break;
    }

    LogMessage("[Trace] Wine process list summary: entries=%lu "
               "current_pid=%lu found=%d parent_pid=%lu "
               "buffer=%lu returned=%lu",
               count, currentPid, currentFound, currentParent,
               bufferLength, returnedLength);
}

static void EmuFillSystemModuleEntry(char* entry, ULONG loadIndex) {
    static const char full[] =
        "\\SystemRoot\\System32\\usrdrv017964.sys";
    ULONG imageSize = g_SysImageSize ? g_SysImageSize : 0xF000;
    ZeroMemory(entry, EMU_SYSMOD_ENTRY_SIZE);
    *(ULONG64*)(entry + 16) = EMU_FAKE_DRIVER_BASE;
    *(ULONG*)(entry + 24)   = imageSize;
    *(USHORT*)(entry + 32)  = (USHORT)loadIndex;
    *(USHORT*)(entry + 36)  = 1;
    *(USHORT*)(entry + 38)  =
        (USHORT)(sizeof("\\SystemRoot\\System32\\") - 1);
    memcpy(entry + 40, full, sizeof(full));
}

NTSTATUS NTAPI EmuHookedNtQuerySystemInformationC(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength) {
    void* caller = _ReturnAddress();
    NTSTATUS st = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (g_TraceEnabled &&
        (SystemInformationClass == 0x03 ||
         SystemInformationClass == 0x05)) {
        LogMessage("[Trace] NtQuerySystemInformation class=0x%lX "
                   "buffer=%p length=%lu -> 0x%08lX return=%lu",
                   SystemInformationClass,
                   SystemInformation,
                   SystemInformationLength,
                   (ULONG)st,
                   ReturnLength ? *ReturnLength : 0);
        EmuLogAddress("system-information caller:", caller);
    }

    if (SystemInformationClass == 0x05 && NT_SUCCESS(st)) {
        EmuTraceSystemProcessList(
            SystemInformation,
            SystemInformationLength,
            ReturnLength ? *ReturnLength : 0);
    }

    if (SystemInformationClass == 0x0B) { /* SystemModuleInformation */
        ULONG returned = ReturnLength ? *ReturnLength : 0;
        if (g_TraceEnabled) {
            LogMessage("[Trace] modules NtQuerySystemInformation(0x0B, "
                       "buffer=%lu) -> 0x%08lX return=%lu",
                       SystemInformationLength, (ULONG)st, returned);
            EmuLogAddress("module-list probe caller:", caller);
        }
        if (NT_SUCCESS(st) && SystemInformation) {
            ULONG count = *(ULONG*)SystemInformation;
            ULONG need  = 8 + (count + 1) * EMU_SYSMOD_ENTRY_SIZE;
            if (need <= SystemInformationLength) {
                char* entry = (char*)SystemInformation + 8 + (SIZE_T)count * EMU_SYSMOD_ENTRY_SIZE;
                ULONG imageSize = g_SysImageSize ? g_SysImageSize : 0xF000;
                EmuFillSystemModuleEntry(entry, count);
                *(ULONG*)SystemInformation = count + 1;
                if (ReturnLength) *ReturnLength = need;
                LogMessage("[Emu] SystemModuleInformation: appended fake "
                           "usrdrv017964 entry (%lu modules, base=%p, "
                           "size=0x%lX)",
                           count + 1, (void*)EMU_FAKE_DRIVER_BASE, imageSize);
                return STATUS_SUCCESS;
            }
            if (ReturnLength) *ReturnLength = need;
            LogMessage("[Emu] SystemModuleInformation buffer too small for fake entry (%lu < %lu); asking caller to grow", SystemInformationLength, need);
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if (st == STATUS_INFO_LENGTH_MISMATCH && ReturnLength) {
            if (*ReturnLength)
                *ReturnLength += EMU_SYSMOD_ENTRY_SIZE;
            else
                *ReturnLength = 8 + EMU_SYSMOD_ENTRY_SIZE;
            LogMessage("[Emu] SystemModuleInformation real list needs %lu; padded requirement for fake entry", *ReturnLength);
            return st;
        }

        {
            ULONG need = 8 + EMU_SYSMOD_ENTRY_SIZE;
            if (ReturnLength) *ReturnLength = need;
            if (!SystemInformation || SystemInformationLength < need)
                return STATUS_INFO_LENGTH_MISMATCH;
            ZeroMemory(SystemInformation, need);
            *(ULONG*)SystemInformation = 1;
            EmuFillSystemModuleEntry((char*)SystemInformation + 8, 0);
            LogMessage("[Emu] SystemModuleInformation host fallback: "
                       "returned fake-only module list (host status=0x%08lX)",
                       (ULONG)st);
            return STATUS_SUCCESS;
        }
    }

    if (g_TraceEnabled && SystemInformationClass < 512) {
        ULONG64* word = &g_QsiClassLogged[SystemInformationClass >> 6];
        ULONG64 bit = 1ULL << (SystemInformationClass & 63);
        if (!(*word & bit)) {
            *word |= bit;
            LogMessage("[Emu] NtQuerySystemInformation class 0x%lX (first use)", SystemInformationClass);
        }
    }
    return st;
}

#define EMU_MAX_TRACKED_KEYS 16
static HANDLE g_UsrdrvKeys[EMU_MAX_TRACKED_KEYS];

static void EmuTrackKey(HANDLE handle) {
    int i;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < EMU_MAX_TRACKED_KEYS; i++) {
        if (!g_UsrdrvKeys[i]) {
            g_UsrdrvKeys[i] = handle;
            break;
        }
    }
    LeaveCriticalSection(&g_Lock);
}

static BOOL EmuIsTrackedKey(HANDLE handle) {
    int i;
    BOOL found = FALSE;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < EMU_MAX_TRACKED_KEYS; i++) {
        if (g_UsrdrvKeys[i] == handle) {
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_Lock);
    return found;
}

static void EmuUntrackKey(HANDLE handle) {
    int i;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < EMU_MAX_TRACKED_KEYS; i++) {
        if (g_UsrdrvKeys[i] == handle)
            g_UsrdrvKeys[i] = NULL;
    }
    LeaveCriticalSection(&g_Lock);
}

static void EmuCopyUnicodeString(PUNICODE_STRING source,
                                 WCHAR* destination,
                                 SIZE_T destinationChars) {
    SIZE_T chars = 0;
    if (!destination || !destinationChars) return;
    if (source && source->Buffer) {
        chars = source->Length / sizeof(WCHAR);
        if (chars >= destinationChars) chars = destinationChars - 1;
        memcpy(destination, source->Buffer, chars * sizeof(WCHAR));
    }
    destination[chars] = L'\0';
}

static BOOL EmuIsUsrdrvKeyAttributes(POBJECT_ATTRIBUTES attributes) {
    if (!attributes) return FALSE;
    return attributes->ObjectName &&
           attributes->ObjectName->Buffer &&
           EmuWideContainsCI(
               attributes->ObjectName->Buffer,
               attributes->ObjectName->Length / sizeof(WCHAR),
               L"usrdrv017964");
}

static NTSTATUS EmuOpenRegistryCarrier(PHANDLE keyHandle) {
    static WCHAR carrierPath[] = L"\\Registry\\Machine\\Software";
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    name.Buffer = carrierPath;
    name.Length = (USHORT)(sizeof(carrierPath) - sizeof(WCHAR));
    name.MaximumLength = sizeof(carrierPath);
    ZeroMemory(&attributes, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */
    return OriginalNtOpenKey(keyHandle, KEY_READ, &attributes);
}

static NTSTATUS NTAPI HookedNtOpenKey(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {
    if (EmuIsUsrdrvKeyAttributes(ObjectAttributes)) {
        WCHAR name[512];
        NTSTATUS st;
        BOOL carrier = g_ForceVirtualService;
        if (carrier) {
            st = EmuOpenRegistryCarrier(KeyHandle);
        } else {
            st = OriginalNtOpenKey(
                KeyHandle, DesiredAccess, ObjectAttributes);
            if (!NT_SUCCESS(st)) {
                st = EmuOpenRegistryCarrier(KeyHandle);
                carrier = TRUE;
            }
        }
        if (!NT_SUCCESS(st)) return st;
        EmuCopyUnicodeString(ObjectAttributes->ObjectName, name,
                             ARRAYSIZE(name));
        EmuTrackKey(*KeyHandle);
        LogMessage("[Emu] NtOpenKey(\"%ls\") -> emulated service key%s",
                   name, carrier ? " (carrier handle)" : "");
        return STATUS_SUCCESS;
    }
    return OriginalNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

static NTSTATUS NTAPI HookedNtOpenKeyEx(
    PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions) {
    if (EmuIsUsrdrvKeyAttributes(ObjectAttributes)) {
        WCHAR name[512];
        NTSTATUS st;
        BOOL carrier = g_ForceVirtualService;
        if (carrier) {
            st = EmuOpenRegistryCarrier(KeyHandle);
        } else {
            st = OriginalNtOpenKeyEx(
                KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
            if (!NT_SUCCESS(st)) {
                st = EmuOpenRegistryCarrier(KeyHandle);
                carrier = TRUE;
            }
        }
        if (!NT_SUCCESS(st)) return st;
        EmuCopyUnicodeString(ObjectAttributes->ObjectName, name,
                             ARRAYSIZE(name));
        EmuTrackKey(*KeyHandle);
        LogMessage("[Emu] NtOpenKeyEx(\"%ls\") -> emulated service key%s",
                   name, carrier ? " (carrier handle)" : "");
        return STATUS_SUCCESS;
    }
    return OriginalNtOpenKeyEx(
        KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
}

typedef struct _EMU_KVBI {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} EMU_KVBI;

typedef struct _EMU_KVPI { ULONG TitleIndex; ULONG Type; ULONG DataLength; UCHAR Data[1]; } EMU_KVPI;
typedef struct _EMU_KVFI {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} EMU_KVFI;

typedef struct _EMU_KBI {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} EMU_KBI;

typedef struct _EMU_KFI {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} EMU_KFI;

typedef struct _EMU_KNI {
    ULONG NameLength;
    WCHAR Name[1];
} EMU_KNI;

typedef struct _EMU_REG_VALUE {
    const WCHAR* name;
    ULONG type;
    const BYTE* data;
    ULONG dataLength;
} EMU_REG_VALUE;

static const ULONG g_RegStart = SERVICE_DEMAND_START;
static const ULONG g_RegType = SERVICE_KERNEL_DRIVER;
static const ULONG g_RegErrorControl = SERVICE_ERROR_NORMAL;
static const WCHAR g_RegImagePath[] =
    L"\\??\\C:\\Windows\\System32\\usrdrv017964.sys";
static const WCHAR g_RegDisplayName[] = L"usrdrv017964";

static BOOL EmuRegistryValueAt(ULONG index, EMU_REG_VALUE* value) {
    static const WCHAR startName[] = L"Start";
    static const WCHAR typeName[] = L"Type";
    static const WCHAR errorName[] = L"ErrorControl";
    static const WCHAR imageName[] = L"ImagePath";
    static const WCHAR displayName[] = L"DisplayName";
    if (!value) return FALSE;
    switch (index) {
    case 0:
        value->name = startName;
        value->type = REG_DWORD;
        value->data = (const BYTE*)&g_RegStart;
        value->dataLength = sizeof(g_RegStart);
        return TRUE;
    case 1:
        value->name = typeName;
        value->type = REG_DWORD;
        value->data = (const BYTE*)&g_RegType;
        value->dataLength = sizeof(g_RegType);
        return TRUE;
    case 2:
        value->name = errorName;
        value->type = REG_DWORD;
        value->data = (const BYTE*)&g_RegErrorControl;
        value->dataLength = sizeof(g_RegErrorControl);
        return TRUE;
    case 3:
        value->name = imageName;
        value->type = REG_EXPAND_SZ;
        value->data = (const BYTE*)g_RegImagePath;
        value->dataLength = sizeof(g_RegImagePath);
        return TRUE;
    case 4:
        value->name = displayName;
        value->type = REG_SZ;
        value->data = (const BYTE*)g_RegDisplayName;
        value->dataLength = sizeof(g_RegDisplayName);
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL EmuRegistryValueByName(
    PUNICODE_STRING valueName, EMU_REG_VALUE* value) {
    WCHAR name[64];
    ULONG i;
    EmuCopyUnicodeString(valueName, name, ARRAYSIZE(name));
    for (i = 0; EmuRegistryValueAt(i, value); i++) {
        if (_wcsicmp(name, value->name) == 0) return TRUE;
    }
    return FALSE;
}

static NTSTATUS EmuFillRegistryValueInformation(
    const EMU_REG_VALUE* value, ULONG infoClass, PVOID information,
    ULONG length, PULONG resultLength) {
    ULONG nameBytes = (ULONG)(wcslen(value->name) * sizeof(WCHAR));
    ULONG required;
    if (infoClass == 0) { /* KeyValueBasicInformation */
        EMU_KVBI* out;
        required = FIELD_OFFSET(EMU_KVBI, Name) + nameBytes;
        if (resultLength) *resultLength = required;
        if (!information || length < required) return STATUS_BUFFER_TOO_SMALL;
        out = (EMU_KVBI*)information;
        ZeroMemory(out, required);
        out->Type = value->type;
        out->NameLength = nameBytes;
        memcpy(out->Name, value->name, nameBytes);
        return STATUS_SUCCESS;
    }
    if (infoClass == 1 || infoClass == 3) {
        EMU_KVFI* out;
        ULONG alignment = infoClass == 3 ? 8 : 4;
        ULONG dataOffset =
            (FIELD_OFFSET(EMU_KVFI, Name) + nameBytes + alignment - 1) &
            ~(alignment - 1);
        required = dataOffset + value->dataLength;
        if (resultLength) *resultLength = required;
        if (!information || length < required) return STATUS_BUFFER_TOO_SMALL;
        out = (EMU_KVFI*)information;
        ZeroMemory(out, required);
        out->Type = value->type;
        out->DataOffset = dataOffset;
        out->DataLength = value->dataLength;
        out->NameLength = nameBytes;
        memcpy(out->Name, value->name, nameBytes);
        memcpy((BYTE*)out + dataOffset, value->data, value->dataLength);
        return STATUS_SUCCESS;
    }
    if (infoClass == 2 || infoClass == 4) {
        EMU_KVPI* out;
        required = FIELD_OFFSET(EMU_KVPI, Data) + value->dataLength;
        if (resultLength) *resultLength = required;
        if (!information || length < required) return STATUS_BUFFER_TOO_SMALL;
        out = (EMU_KVPI*)information;
        ZeroMemory(out, required);
        out->Type = value->type;
        out->DataLength = value->dataLength;
        memcpy(out->Data, value->data, value->dataLength);
        return STATUS_SUCCESS;
    }
    if (resultLength) *resultLength = 0;
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS NTAPI HookedNtQueryValueKey(
    HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength) {
    EMU_REG_VALUE value;
    NTSTATUS st;
    if (!EmuIsTrackedKey(KeyHandle))
        return OriginalNtQueryValueKey(
            KeyHandle, ValueName, KeyValueInformationClass,
            KeyValueInformation, Length, ResultLength);
    if (!EmuRegistryValueByName(ValueName, &value)) {
        if (ResultLength) *ResultLength = 0;
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    st = EmuFillRegistryValueInformation(
        &value, KeyValueInformationClass, KeyValueInformation,
        Length, ResultLength);
    if (g_TraceEnabled)
        LogMessage("[Trace] registry query \"%ls\" class=%lu -> 0x%08lX",
                   value.name, KeyValueInformationClass, (ULONG)st);
    return st;
}

static NTSTATUS NTAPI HookedNtQueryKey(
    HANDLE KeyHandle, ULONG KeyInformationClass, PVOID KeyInformation,
    ULONG Length, PULONG ResultLength) {
    static const WCHAR leaf[] = L"usrdrv017964";
    static const WCHAR full[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\"
        L"usrdrv017964";
    ULONG nameBytes;
    ULONG required;
    if (!EmuIsTrackedKey(KeyHandle))
        return OriginalNtQueryKey(
            KeyHandle, KeyInformationClass, KeyInformation,
            Length, ResultLength);
    if (KeyInformationClass == 0) { 
        EMU_KBI* out;
        nameBytes = sizeof(leaf) - sizeof(WCHAR);
        required = FIELD_OFFSET(EMU_KBI, Name) + nameBytes;
        if (ResultLength) *ResultLength = required;
        if (!KeyInformation || Length < required)
            return STATUS_BUFFER_TOO_SMALL;
        out = (EMU_KBI*)KeyInformation;
        ZeroMemory(out, required);
        out->NameLength = nameBytes;
        memcpy(out->Name, leaf, nameBytes);
        return STATUS_SUCCESS;
    }
    if (KeyInformationClass == 2) { 
        EMU_KFI* out;
        required = FIELD_OFFSET(EMU_KFI, Class);
        if (ResultLength) *ResultLength = required;
        if (!KeyInformation || Length < required)
            return STATUS_BUFFER_TOO_SMALL;
        out = (EMU_KFI*)KeyInformation;
        ZeroMemory(out, required);
        out->Values = 5;
        out->MaxValueNameLen = sizeof(L"ErrorControl") - sizeof(WCHAR);
        out->MaxValueDataLen = sizeof(g_RegImagePath);
        return STATUS_SUCCESS;
    }
    if (KeyInformationClass == 3) {
        EMU_KNI* out;
        nameBytes = sizeof(full) - sizeof(WCHAR);
        required = FIELD_OFFSET(EMU_KNI, Name) + nameBytes;
        if (ResultLength) *ResultLength = required;
        if (!KeyInformation || Length < required)
            return STATUS_BUFFER_TOO_SMALL;
        out = (EMU_KNI*)KeyInformation;
        ZeroMemory(out, required);
        out->NameLength = nameBytes;
        memcpy(out->Name, full, nameBytes);
        return STATUS_SUCCESS;
    }
    if (ResultLength) *ResultLength = 0;
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS NTAPI HookedNtEnumerateKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    if (EmuIsTrackedKey(KeyHandle)) {
        if (ResultLength) *ResultLength = 0;
        return STATUS_NO_MORE_ENTRIES;
    }
    return OriginalNtEnumerateKey(
        KeyHandle, Index, KeyInformationClass, KeyInformation,
        Length, ResultLength);
}

static NTSTATUS NTAPI HookedNtEnumerateValueKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    EMU_REG_VALUE value;
    if (!EmuIsTrackedKey(KeyHandle))
        return OriginalNtEnumerateValueKey(
            KeyHandle, Index, KeyValueInformationClass,
            KeyValueInformation, Length, ResultLength);
    if (!EmuRegistryValueAt(Index, &value)) {
        if (ResultLength) *ResultLength = 0;
        return STATUS_NO_MORE_ENTRIES;
    }
    return EmuFillRegistryValueInformation(
        &value, KeyValueInformationClass, KeyValueInformation,
        Length, ResultLength);
}

static NTSTATUS NTAPI HookedNtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        EmuNameMatchesBuf(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(WCHAR))) {
        LogMessage("[Emu] NtOpenSymbolicLinkObject(\"%ls\") -> fake handle", ObjectAttributes->ObjectName->Buffer);
        *LinkHandle = EMU_FAKE_SYMLINK_HANDLE;
        return STATUS_SUCCESS;
    }
    return OriginalNtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes);
}

static NTSTATUS NTAPI HookedNtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength) {
    if (LinkHandle == EMU_FAKE_SYMLINK_HANDLE) {
        static const WCHAR target[] = L"\\Device\\Htsysm6321";
        ULONG bytes = (ULONG)(sizeof(target) - sizeof(WCHAR));
        if (!LinkTarget || LinkTarget->MaximumLength < bytes + sizeof(WCHAR)) {
            if (ReturnedLength) *ReturnedLength = bytes;
            return STATUS_BUFFER_TOO_SMALL;
        }
        memcpy(LinkTarget->Buffer, target, bytes + sizeof(WCHAR));
        LinkTarget->Length = (USHORT)bytes;
        if (ReturnedLength) *ReturnedLength = bytes;
        LogMessage("[Emu] NtQuerySymbolicLinkObject(fake) -> \"%ls\"", target);
        return STATUS_SUCCESS;
    }
    return OriginalNtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength);
}

static DWORD g_InjectedPids[32];
static int   g_InjectedPidCount = 0;

static BOOL EmuAlreadyInjected(DWORD pid) {
    int i; BOOL found = FALSE;
    EnterCriticalSection(&g_Lock);
    for (i = 0; i < g_InjectedPidCount; i++) if (g_InjectedPids[i] == pid) { found = TRUE; break; }
    LeaveCriticalSection(&g_Lock);
    return found;
}

static void EmuRememberInjected(DWORD pid) {
    EnterCriticalSection(&g_Lock);
    if (g_InjectedPidCount < 32) g_InjectedPids[g_InjectedPidCount++] = pid;
    LeaveCriticalSection(&g_Lock);
}

static BOOL EmuIsGameImage(DWORD pid) {
    WCHAR path[MAX_PATH];
    DWORD sz = MAX_PATH;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    const WCHAR* base;
    BOOL ok;
    if (!h) return FALSE;
    ok = QueryFullProcessImageNameW(h, 0, path, &sz);
    CloseHandle(h);
    if (!ok) return FALSE;
    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    return _wcsicmp(base, L"hololive-Dreams.exe") == 0;
}

static BOOL EmuGetSnapshotProcessInfo(
    DWORD pid,
    DWORD* parentPid,
    WCHAR* imageName,
    SIZE_T imageNameChars) {
    PROCESSENTRY32W pe;
    HANDLE snapshot;
    BOOL found = FALSE;

    if (parentPid) *parentPid = 0;
    if (imageName && imageNameChars) imageName[0] = L'\0';
    pe.dwSize = sizeof(pe);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                if (parentPid) *parentPid = pe.th32ParentProcessID;
                if (imageName && imageNameChars) {
                    wcsncpy_s(
                        imageName, imageNameChars, pe.szExeFile, _TRUNCATE);
                }
                found = TRUE;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return found;
}

static BOOL EmuContainsGameExe(const WCHAR* text) {
    static const WCHAR needle[] = L"hololive-Dreams.exe";
    SIZE_T needleChars = ARRAYSIZE(needle) - 1;

    if (!text) return FALSE;
    while (*text) {
        if (_wcsnicmp(text, needle, needleChars) == 0) return TRUE;
        text++;
    }
    return FALSE;
}

static BOOL EmuUnicodeContainsGameExe(const UNICODE_STRING* text) {
    static const WCHAR needle[] = L"hololive-Dreams.exe";
    USHORT textChars;
    USHORT needleChars = (USHORT)(ARRAYSIZE(needle) - 1);
    USHORT i;

    if (!text || !text->Buffer) return FALSE;
    textChars = text->Length / sizeof(WCHAR);
    if (textChars < needleChars) return FALSE;
    for (i = 0; i + needleChars <= textChars; i++) {
        if (_wcsnicmp(text->Buffer + i, needle, needleChars) == 0)
            return TRUE;
    }
    return FALSE;
}

static ULONG_PTR EmuFindRemoteModuleBase(
    DWORD pid, const char* moduleName) {
    MODULEENTRY32 entry;
    HANDLE snapshot;
    ULONG_PTR base = 0;
    entry.dwSize = sizeof(entry);
    snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Module32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szModule, moduleName) == 0) {
                base = (ULONG_PTR)entry.modBaseAddr;
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return base;
}

static LPTHREAD_START_ROUTINE EmuRemoteLoadLibraryAddress(DWORD pid) {
    HMODULE localKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE localProcedureModule = NULL;
    FARPROC localLoadLibrary =
        localKernel32 ? GetProcAddress(localKernel32, "LoadLibraryA") : NULL;
    ULONG_PTR remoteProcedureModule;
    char modulePath[MAX_PATH];
    const char* moduleName;
    if (!localKernel32 || !localLoadLibrary) return NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)localLoadLibrary, &localProcedureModule) ||
        !GetModuleFileNameA(
            localProcedureModule, modulePath, ARRAYSIZE(modulePath))) {
        localProcedureModule = localKernel32;
        strcpy_s(modulePath, ARRAYSIZE(modulePath), "kernel32.dll");
    }
    moduleName = strrchr(modulePath, '\\');
    if (!moduleName) moduleName = strrchr(modulePath, '/');
    moduleName = moduleName ? moduleName + 1 : modulePath;
    remoteProcedureModule =
        EmuFindRemoteModuleBase(pid, moduleName);
    if (!remoteProcedureModule) {
        if (g_TraceEnabled)
            LogMessage("[Trace] remote %s not enumerable in PID %lu; "
                       "using shared LoadLibraryA address",
                       moduleName, pid);
        return (LPTHREAD_START_ROUTINE)localLoadLibrary;
    }
    return (LPTHREAD_START_ROUTINE)(
        remoteProcedureModule +
        ((ULONG_PTR)localLoadLibrary -
         (ULONG_PTR)localProcedureModule));
}

static void EmuInjectIntoProcess(DWORD pid) {
    char dllPath[MAX_PATH];
    SIZE_T pathSize;
    HANDLE hProcess, hThread;
    LPVOID remote;
    LPTHREAD_START_ROUTINE remoteLoadLibrary;

    GetModuleFileNameA(g_hModule, dllPath, MAX_PATH);
    pathSize = strlen(dllPath) + 1;

    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        LogMessage("[Emu]   inject into PID %lu: OpenProcess failed (%lu)", pid, GetLastError());
        return;
    }
    remote = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote) {
        remoteLoadLibrary = EmuRemoteLoadLibraryAddress(pid);
        if (!remoteLoadLibrary ||
            !WriteProcessMemory(
                hProcess, remote, dllPath, pathSize, NULL)) {
            LogMessage("[Emu]   inject into PID %lu: failed to prepare "
                       "remote LoadLibrary (%lu)", pid, GetLastError());
            VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return;
        }
        hThread = CreateRemoteThread(
            hProcess, NULL, 0, remoteLoadLibrary, remote, 0, NULL);
        if (hThread) {
            DWORD wait = WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
            if (wait == WAIT_OBJECT_0)
                LogMessage("[Emu]   injected into PID %lu", pid);
            else
                LogMessage("[Emu]   inject into PID %lu: LoadLibrary "
                           "thread timed out", pid);
        } else {
            LogMessage("[Emu]   inject into PID %lu: CreateRemoteThread failed (%lu)", pid, GetLastError());
        }
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    }
    CloseHandle(hProcess);
}

static BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL isGameChild =
        EmuContainsGameExe(lpApplicationName) ||
        EmuContainsGameExe(lpCommandLine);
    BOOL callerRequestedSuspended =
        (dwCreationFlags & CREATE_SUSPENDED) != 0;
    DWORD effectiveFlags = dwCreationFlags;
    BOOL ok;

    if (isGameChild && !callerRequestedSuspended) {
        effectiveFlags |= CREATE_SUSPENDED;
        LogMessage("[Emu] CreateProcessW: temporarily suspending game child "
                   "for pre-entry injection");
    }

    ok = OriginalCreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        effectiveFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    if (ok && isGameChild && !callerRequestedSuspended &&
        lpProcessInformation && lpProcessInformation->hThread) {
        DWORD childPid = lpProcessInformation->dwProcessId;
        LogMessage("[Emu] CreateProcessW: game child PID %lu created "
                   "suspended; injecting before entry", childPid);
        EmuRememberInjected(childPid);
        EmuInjectIntoProcess(childPid);
        if (ResumeThread(lpProcessInformation->hThread) == (DWORD)-1) {
            LogMessage("[Emu] CreateProcessW: failed to release game child "
                       "PID %lu (%lu)", childPid, GetLastError());
        } else {
            LogMessage("[Emu] CreateProcessW: game child PID %lu released",
                       childPid);
        }
    }

    return ok;
}

static NTSTATUS NTAPI HookedNtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList)
{
    BOOL isGameChild = ProcessParameters &&
        (EmuUnicodeContainsGameExe(&ProcessParameters->ImagePathName) ||
         EmuUnicodeContainsGameExe(&ProcessParameters->CommandLine));
    BOOL callerRequestedSuspended = (ThreadFlags & 1) != 0;
    ULONG effectiveThreadFlags = ThreadFlags;
    NTSTATUS status;

    if (isGameChild && !callerRequestedSuspended) {
        effectiveThreadFlags |= 1; // THREAD_CREATE_FLAGS_CREATE_SUSPENDED 
        LogMessage("[Emu] NtCreateUserProcess: temporarily suspending game "
                   "child for pre-entry injection");
    }

    status = OriginalNtCreateUserProcess(
        ProcessHandle,
        ThreadHandle,
        ProcessDesiredAccess,
        ThreadDesiredAccess,
        ProcessObjectAttributes,
        ThreadObjectAttributes,
        ProcessFlags,
        effectiveThreadFlags,
        ProcessParameters,
        CreateInfo,
        AttributeList);

    if (NT_SUCCESS(status) && isGameChild && !callerRequestedSuspended &&
        ProcessHandle && *ProcessHandle && ThreadHandle && *ThreadHandle) {
        DWORD childPid = GetProcessId(*ProcessHandle);
        LogMessage("[Emu] NtCreateUserProcess: game child PID %lu created "
                   "suspended; injecting before entry", childPid);
        EmuRememberInjected(childPid);
        EmuInjectIntoProcess(childPid);
        if (ResumeThread(*ThreadHandle) == (DWORD)-1) {
            LogMessage("[Emu] NtCreateUserProcess: failed to release game "
                       "child PID %lu (%lu)", childPid, GetLastError());
        } else {
            LogMessage("[Emu] NtCreateUserProcess: game child PID %lu "
                       "released", childPid);
        }
    }

    return status;
}

static NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    DWORD pid = ThreadHandle ? GetProcessIdOfThread(ThreadHandle) : 0;
    if (pid && pid != GetCurrentProcessId() && !EmuAlreadyInjected(pid)) {
        BOOL gameImage = EmuIsGameImage(pid);
        DWORD snapshotParent = 0;
        WCHAR snapshotImage[MAX_PATH];
        BOOL snapshotKnown = FALSE;
        BOOL directChild = FALSE;
        BOOL snapshotGame = FALSE;

        snapshotImage[0] = L'\0';
        if (!gameImage) {
            snapshotKnown = EmuGetSnapshotProcessInfo(
                pid, &snapshotParent, snapshotImage,
                ARRAYSIZE(snapshotImage));
            directChild = snapshotKnown &&
                          snapshotParent == GetCurrentProcessId();
            snapshotGame = snapshotImage[0] &&
                           _wcsicmp(
                               snapshotImage,
                               L"hololive-Dreams.exe") == 0;
        }

        // yeah, nah king. 
        if (gameImage ||
            (directChild && (!snapshotImage[0] || snapshotGame))) {
            if (!gameImage) {
                LogMessage("[Emu] NtResumeThread: PID %lu image name is not "
                           "ready; accepting direct-child fallback "
                           "(snapshot=\"%ls\")",
                           pid,
                           snapshotImage[0]
                               ? snapshotImage
                               : L"<unnamed>");
            }
            LogMessage("[Emu] NtResumeThread: game child PID %lu resuming; injecting before release", pid);
            EmuRememberInjected(pid);
            EmuInjectIntoProcess(pid);
        } else if (directChild && snapshotImage[0]) {
            LogMessage("[Emu] NtResumeThread: skipping non-game direct child "
                       "PID %lu image=\"%ls\"", pid, snapshotImage);
        } else {
            LogMessage("[Emu] NtResumeThread: cross-process PID %lu was not "
                       "recognized as a game/direct child", pid);
        }
    }
    return OriginalNtResumeThread(ThreadHandle, SuspendCount);
}

static void EmuInstallHook(void* target, void* detour, void** original, const char* name) {
    MH_STATUS status;
    if (!target) {
        LogMessage("[Emu] hook target %s not found", name);
        return;
    }
    status = MH_CreateHook(target, detour, original);
    if (status != MH_OK) {
        LogMessage("[Emu] MH_CreateHook failed for %s: %s (%d)",
                   name, MH_StatusToString(status), (int)status);
    }
}

//HOLY FUCKING SHIT: 40 000
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HMODULE hKernelBase, hNtdll, hAdvapi32;
        BOOL isWine;

        g_hModule = hModule;
        EmuInitializeConfiguration();
        DisableThreadLibraryCalls(hModule);
        hNtdll = GetModuleHandleA("ntdll.dll");
        isWine = hNtdll &&
                 GetProcAddress(hNtdll, "wine_get_version") != NULL;
        g_IsWine = isWine;
        if (isWine) {
            LogMessage("[Emu] Wine detected; vectored crash observer disabled");
        } else {
            AddVectoredExceptionHandler(1, EmuCrashObserver);
        }
        InitializeCriticalSection(&g_Lock);
        ZeroMemory(&g_State, sizeof(g_State));
        g_SvcRunning = TRUE;

        if (MH_Initialize() != MH_OK) {
            LogMessage("[Emu] MH_Initialize failed");
            return TRUE;
        }

        hKernelBase = GetModuleHandleA("kernelbase.dll");
        hAdvapi32   = GetModuleHandleA("advapi32.dll");
        if (!hAdvapi32) hAdvapi32 = LoadLibraryA("advapi32.dll");

        EmuInstallHook(GetProcAddress(hKernelBase, "CreateFileW"),      &HookedCreateFileW,      (LPVOID*)&OriginalCreateFileW,      "CreateFileW");
        EmuInstallHook(GetProcAddress(hKernelBase, "GetFileAttributesW"), &HookedGetFileAttributesW, (LPVOID*)&OriginalGetFileAttributesW, "GetFileAttributesW");
        EmuInstallHook(GetProcAddress(hKernelBase, "GetFileAttributesExW"), &HookedGetFileAttributesExW, (LPVOID*)&OriginalGetFileAttributesExW, "GetFileAttributesExW");
        EmuInstallHook(GetProcAddress(hKernelBase, "QueryDosDeviceW"),  &HookedQueryDosDeviceW,  (LPVOID*)&OriginalQueryDosDeviceW,  "QueryDosDeviceW");
        EmuInstallHook(GetProcAddress(hKernelBase, "CreateProcessW"),   &HookedCreateProcessW,   (LPVOID*)&OriginalCreateProcessW,   "CreateProcessW");
        EmuInstallHook(GetProcAddress(hKernelBase, "DeviceIoControl"),  &HookedDeviceIoControl,  (LPVOID*)&OriginalDeviceIoControl,  "DeviceIoControl");
        EmuInstallHook(GetProcAddress(hKernelBase, "CloseHandle"),      &HookedCloseHandle,      (LPVOID*)&OriginalCloseHandle,      "CloseHandle");

        EmuInstallHook(GetProcAddress(hNtdll, "NtCreateFile"),          &HookedNtCreateFile,     (LPVOID*)&OriginalNtCreateFile,     "NtCreateFile");
        EmuInstallHook(GetProcAddress(hNtdll, "NtQueryAttributesFile"), &HookedNtQueryAttributesFile, (LPVOID*)&OriginalNtQueryAttributesFile, "NtQueryAttributesFile");
        EmuInstallHook(GetProcAddress(hNtdll, "NtQueryFullAttributesFile"), &HookedNtQueryFullAttributesFile, (LPVOID*)&OriginalNtQueryFullAttributesFile, "NtQueryFullAttributesFile");
        EmuInstallHook(GetProcAddress(hNtdll, "NtCreateUserProcess"),   &HookedNtCreateUserProcess, (LPVOID*)&OriginalNtCreateUserProcess, "NtCreateUserProcess");
        EmuInstallHook(GetProcAddress(hNtdll, "NtOpenFile"),            &HookedNtOpenFile,       (LPVOID*)&OriginalNtOpenFile,       "NtOpenFile");
        EmuInstallHook(GetProcAddress(hNtdll, "NtDeviceIoControlFile"), &HookedNtDeviceIoControlFile, (LPVOID*)&OriginalNtDeviceIoControlFile, "NtDeviceIoControlFile");
        EmuInstallHook(GetProcAddress(hNtdll, "NtClose"),               &HookedNtClose,          (LPVOID*)&OriginalNtClose,          "NtClose");
        EmuInstallHook(GetProcAddress(hNtdll, "NtLoadDriver"),          &HookedNtLoadDriver,     (LPVOID*)&OriginalNtLoadDriver,     "NtLoadDriver");

        EmuInstallHook(
            GetProcAddress(hNtdll, "NtQuerySystemInformation"),
            &EmuNtQuerySystemInformationThunk,
            (LPVOID*)&OriginalNtQuerySystemInformation,
            "NtQuerySystemInformation");
            //FUCKING WINE AND ITS DOGSHIT IMPLS FUCKING HELL
        if (isWine) {
            LogMessage("[Emu] Wine compatibility: "
                       "RtlExitUserProcess teardown hook disabled");
            EmuInstallHook(
                GetProcAddress(hNtdll, "NtTerminateProcess"),
                &EmuNtTerminateProcessThunk,
                (LPVOID*)&OriginalNtTerminateProcess,
                "NtTerminateProcess");
            EmuInstallHook(
                GetProcAddress(hNtdll, "NtRaiseException"),
                &EmuNtRaiseExceptionThunk,
                (LPVOID*)&OriginalNtRaiseException,
                "NtRaiseException");
        } else {
            EmuInstallHook(
                GetProcAddress(hNtdll, "RtlExitUserProcess"),
                &HookedRtlExitUserProcess,
                (LPVOID*)&OriginalRtlExitUserProcess,
                "RtlExitUserProcess");
        }
        EmuInstallHook(GetProcAddress(hNtdll, "NtOpenKey"),             &HookedNtOpenKey,        (LPVOID*)&OriginalNtOpenKey,        "NtOpenKey");
        EmuInstallHook(GetProcAddress(hNtdll, "NtOpenKeyEx"),           &HookedNtOpenKeyEx,      (LPVOID*)&OriginalNtOpenKeyEx,      "NtOpenKeyEx");
        EmuInstallHook(GetProcAddress(hNtdll, "NtQueryValueKey"),       &HookedNtQueryValueKey,  (LPVOID*)&OriginalNtQueryValueKey,  "NtQueryValueKey");
        EmuInstallHook(GetProcAddress(hNtdll, "NtQueryKey"),            &HookedNtQueryKey,       (LPVOID*)&OriginalNtQueryKey,       "NtQueryKey");
        EmuInstallHook(GetProcAddress(hNtdll, "NtEnumerateKey"),        &HookedNtEnumerateKey,   (LPVOID*)&OriginalNtEnumerateKey,   "NtEnumerateKey");
        EmuInstallHook(GetProcAddress(hNtdll, "NtEnumerateValueKey"),   &HookedNtEnumerateValueKey, (LPVOID*)&OriginalNtEnumerateValueKey, "NtEnumerateValueKey");
        EmuInstallHook(GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject"), &HookedNtOpenSymbolicLinkObject, (LPVOID*)&OriginalNtOpenSymbolicLinkObject, "NtOpenSymbolicLinkObject");
        EmuInstallHook(GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject"), &HookedNtQuerySymbolicLinkObject, (LPVOID*)&OriginalNtQuerySymbolicLinkObject, "NtQuerySymbolicLinkObject");
        EmuInstallHook(GetProcAddress(hNtdll, "NtResumeThread"),        &HookedNtResumeThread,   (LPVOID*)&OriginalNtResumeThread,   "NtResumeThread");

        EmuInstallHook(GetProcAddress(hAdvapi32, "OpenServiceW"),       &HookedOpenServiceW,     (LPVOID*)&OriginalOpenServiceW,     "OpenServiceW");
        EmuInstallHook(GetProcAddress(hAdvapi32, "OpenServiceA"),       &HookedOpenServiceA,     (LPVOID*)&OriginalOpenServiceA,     "OpenServiceA");
        EmuInstallHook(GetProcAddress(hAdvapi32, "CreateServiceW"),     &HookedCreateServiceW,   (LPVOID*)&OriginalCreateServiceW,   "CreateServiceW");
        EmuInstallHook(GetProcAddress(hAdvapi32, "CreateServiceA"),     &HookedCreateServiceA,   (LPVOID*)&OriginalCreateServiceA,   "CreateServiceA");
        EmuInstallHook(GetProcAddress(hAdvapi32, "StartServiceW"),      &HookedStartServiceW,    (LPVOID*)&OriginalStartServiceW,    "StartServiceW");
        EmuInstallHook(GetProcAddress(hAdvapi32, "StartServiceA"),      &HookedStartServiceA,    (LPVOID*)&OriginalStartServiceA,    "StartServiceA");
        EmuInstallHook(GetProcAddress(hAdvapi32, "QueryServiceStatus"), &HookedQueryServiceStatus, (LPVOID*)&OriginalQueryServiceStatus, "QueryServiceStatus");
        EmuInstallHook(GetProcAddress(hAdvapi32, "QueryServiceStatusEx"), &HookedQueryServiceStatusEx, (LPVOID*)&OriginalQueryServiceStatusEx, "QueryServiceStatusEx");
        EmuInstallHook(GetProcAddress(hAdvapi32, "QueryServiceConfigW"), &HookedQueryServiceConfigW, (LPVOID*)&OriginalQueryServiceConfigW, "QueryServiceConfigW");
        EmuInstallHook(GetProcAddress(hAdvapi32, "QueryServiceConfigA"), &HookedQueryServiceConfigA, (LPVOID*)&OriginalQueryServiceConfigA, "QueryServiceConfigA");
        EmuInstallHook(GetProcAddress(hAdvapi32, "EnumServicesStatusExW"), &HookedEnumServicesStatusExW, (LPVOID*)&OriginalEnumServicesStatusExW, "EnumServicesStatusExW");
        EmuInstallHook(GetProcAddress(hAdvapi32, "EnumServicesStatusExA"), &HookedEnumServicesStatusExA, (LPVOID*)&OriginalEnumServicesStatusExA, "EnumServicesStatusExA");
        EmuInstallHook(GetProcAddress(hAdvapi32, "ControlService"),     &HookedControlService,   (LPVOID*)&OriginalControlService,   "ControlService");
        EmuInstallHook(GetProcAddress(hAdvapi32, "DeleteService"),      &HookedDeleteService,    (LPVOID*)&OriginalDeleteService,    "DeleteService");
        EmuInstallHook(GetProcAddress(hAdvapi32, "CloseServiceHandle"), &HookedCloseServiceHandle, (LPVOID*)&OriginalCloseServiceHandle, "CloseServiceHandle");
        EmuInstallHook(GetProcAddress(hAdvapi32, "ChangeServiceConfigW"), &HookedChangeServiceConfigW, (LPVOID*)&OriginalChangeServiceConfigW, "ChangeServiceConfigW");
        EmuInstallHook(GetProcAddress(hAdvapi32, "ChangeServiceConfigA"), &HookedChangeServiceConfigA, (LPVOID*)&OriginalChangeServiceConfigA, "ChangeServiceConfigA");

        MH_EnableHook(MH_ALL_HOOKS);

        EmuLoadSysBytes();
        InterlockedExchange64(
            (volatile LONG64*)&g_EmulatorReadyCookie,
            (LONG64)EMU_READY_COOKIE);
        LogMessage("[Emu] v5 initialized (trace=%s, log=\"%s\", "
                   "driver_image=%s, virtual_service=%s)",
                   g_TraceEnabled ? "on" : "off", g_LogPath,
                   g_SysBytes ? "ready" : "missing",
                   g_ForceVirtualService ? "forced" : "automatic");
    }
    // JAPANESE ENGINEERS AINT SHIT, KYMERA ON TOP!
    return TRUE;
}
