#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef LONG(NTAPI *pNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT LPVOID lpBytesBuffer
);

typedef LONG(NTAPI *pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return TRUE;
}

static BOOL IsProcessSuspended(DWORD pid, BOOL* stateKnown) {
    pNtQueryInformationThread NtQueryInformationThread;
    THREADENTRY32 te32;
    HANDLE hSnap;
    BOOL sawQuery = FALSE;
    BOOL suspended = FALSE;

    *stateKnown = FALSE;
    NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread) return FALSE;

    te32.dwSize = sizeof(te32);
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;

    if (Thread32First(hSnap, &te32)) {
        do {
            HANDLE hThread;
            ULONG suspendCount = 0;
            LONG status;

            if (te32.th32OwnerProcessID != pid) continue;
            hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                                 te32.th32ThreadID);
            if (!hThread) continue;

            status = NtQueryInformationThread(
                hThread,
                35, 
                &suspendCount,
                sizeof(suspendCount),
                NULL);
            CloseHandle(hThread);

            if (status >= 0) {
                sawQuery = TRUE;
                if (suspendCount != 0) {
                    suspended = TRUE;
                    break;
                }
            }
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);
    *stateKnown = sawQuery;
    return suspended;
}

#define EMU_READY_COOKIE 0x484F4C4F454D5531ULL

static ULONG_PTR FindRemoteModuleBase(
    DWORD pid, const char* moduleName) {
    MODULEENTRY32 me;
    HANDLE snapshot;
    ULONG_PTR moduleBase = 0;

    me.dwSize = sizeof(me);
    snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (Module32First(snapshot, &me)) {
        do {
            if (_stricmp(me.szModule, moduleName) == 0) {
                moduleBase = (ULONG_PTR)me.modBaseAddr;
                break;
            }
        } while (Module32Next(snapshot, &me));
    }

    CloseHandle(snapshot);
    return moduleBase;
}

//YEAHH GANG WE HARDCODING THIS
static ULONG_PTR FindEmulatorBase(DWORD pid) {
    return FindRemoteModuleBase(pid, "Emulator.dll");
}

static BOOL IsEmulatorReady(
    DWORD pid,
    ULONG_PTR remoteModuleBase,
    const char* dllPath)
{
    static SIZE_T cookieRva = 0;
    static BOOL cookieRvaResolved = FALSE;
    HANDLE hProcess;
    ULONGLONG remoteCookie = 0;
    SIZE_T bytesRead = 0;

    if (!remoteModuleBase) return FALSE;

    if (!cookieRvaResolved) {
        HMODULE localImage = LoadLibraryExA(
            dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (localImage) {
            const void* localCookie = GetProcAddress(
                localImage, "g_EmulatorReadyCookie");
            if (localCookie) {
                cookieRva =
                    (SIZE_T)((ULONG_PTR)localCookie -
                             (ULONG_PTR)localImage);
            }
            FreeLibrary(localImage);
        }
        cookieRvaResolved = TRUE;
    }

    if (!cookieRva) return FALSE;
    hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
    if (!ReadProcessMemory(
            hProcess,
            (LPCVOID)(remoteModuleBase + cookieRva),
            &remoteCookie,
            sizeof(remoteCookie),
            &bytesRead)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);
    return bytesRead == sizeof(remoteCookie) &&
           remoteCookie == EMU_READY_COOKIE;
}

static BOOL InjectDLL(DWORD pid, const char* dllPath) {
    SIZE_T pathSize;
    SIZE_T written = 0;
    LPVOID pRemoteDllPath;
    HMODULE hKernel32;
    HMODULE hLoadLibraryModule = NULL;
    LPTHREAD_START_ROUTINE pLoadLibrary;
    ULONG_PTR remoteLoadLibraryModule;
    FARPROC localLoadLibrary;
    char loadLibraryModulePath[MAX_PATH];
    const char* loadLibraryModuleName;
    HMODULE hNtdll;
    pNtCreateThreadEx NtCreateThreadEx;
    HANDLE hProcess;

    EnableDebugPrivilege();

    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    pathSize = strlen(dllPath) + 1;
    pRemoteDllPath = VirtualAllocEx(
        hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllPath ||
        !WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, pathSize,
                            &written) ||
        written != pathSize) {
        printf("[-] Failed to prepare remote DLL path: %d\n", GetLastError());
        if (pRemoteDllPath)
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    hKernel32 = GetModuleHandleA("kernel32.dll");
    localLoadLibrary = hKernel32
        ? GetProcAddress(hKernel32, "LoadLibraryA")
        : NULL;
    if (!localLoadLibrary) {
        printf("[-] LoadLibraryA is unavailable in this runtime.\n");
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)localLoadLibrary, &hLoadLibraryModule) ||
        !GetModuleFileNameA(
            hLoadLibraryModule, loadLibraryModulePath,
            ARRAYSIZE(loadLibraryModulePath))) {
        hLoadLibraryModule = hKernel32;
        strcpy_s(loadLibraryModulePath,
                 ARRAYSIZE(loadLibraryModulePath), "kernel32.dll");
    }
    loadLibraryModuleName = strrchr(loadLibraryModulePath, '\\');
    if (!loadLibraryModuleName)
        loadLibraryModuleName = strrchr(loadLibraryModulePath, '/');
    loadLibraryModuleName = loadLibraryModuleName
        ? loadLibraryModuleName + 1
        : loadLibraryModulePath;
    remoteLoadLibraryModule =
        FindRemoteModuleBase(pid, loadLibraryModuleName);
    if (remoteLoadLibraryModule) {
        pLoadLibrary = (LPTHREAD_START_ROUTINE)(
            remoteLoadLibraryModule +
            ((ULONG_PTR)localLoadLibrary -
             (ULONG_PTR)hLoadLibraryModule));
    } else {
        pLoadLibrary = (LPTHREAD_START_ROUTINE)localLoadLibrary;
        printf("[*] Remote %s is not enumerable yet; using the shared "
               "LoadLibraryA address.\n", loadLibraryModuleName);
    }

    hNtdll = GetModuleHandleA("ntdll.dll");
    NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
        hNtdll, "NtCreateThreadEx");

    if (NtCreateThreadEx) {
        HANDLE hThread = NULL;
        DWORD waitResult;
        DWORD loadResult = 0;
        LONG status = NtCreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, NULL, hProcess, pLoadLibrary,
            pRemoteDllPath, FALSE, 0, 0, 0, NULL);
        if (hThread) {
            waitResult = WaitForSingleObject(hThread, 5000);
            if (waitResult == WAIT_OBJECT_0)
                GetExitCodeThread(hThread, &loadResult);
            CloseHandle(hThread);
            if (waitResult == WAIT_OBJECT_0 && loadResult != 0) {
                VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                printf("[+] Injection successful (NtCreateThreadEx, "
                       "LoadLibrary=0x%08lX)!\n", loadResult); // on foenem grave
                return TRUE;
            }
            if (waitResult == WAIT_TIMEOUT) {
                printf("[-] NtCreateThreadEx LoadLibrary timed out.\n");
                CloseHandle(hProcess);
                return FALSE;
            }
            printf("[-] NtCreateThreadEx ran, but LoadLibrary returned "
                   "NULL.\n");
        } else {
            printf("[-] NtCreateThreadEx failed: Status 0x%X\n", status);
        }
    }

    printf("[*] Falling back to CreateRemoteThread...\n");
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0, pLoadLibrary, pRemoteDllPath, 0, NULL);
    if (hThread) {
        DWORD waitResult = WaitForSingleObject(hThread, 5000);
        DWORD loadResult = 0;
        if (waitResult == WAIT_OBJECT_0)
            GetExitCodeThread(hThread, &loadResult);
        CloseHandle(hThread);
        if (waitResult == WAIT_OBJECT_0 && loadResult != 0) {
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            printf("[+] Injection successful (CreateRemoteThread, "
                   "LoadLibrary=0x%08lX)!\n", loadResult);
            return TRUE;
        }
        if (waitResult == WAIT_TIMEOUT) {
            printf("[-] CreateRemoteThread LoadLibrary timed out.\n");
            CloseHandle(hProcess);
            return FALSE;
        }
        printf("[-] CreateRemoteThread ran, but LoadLibrary returned NULL.\n");
    }

    printf("[-] CreateRemoteThread failed: %d\n", GetLastError());
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
}
typedef struct _CANDIDATE {
    DWORD     pid;
    DWORD     parentPid;
    unsigned  generation;
    ULONGLONG firstSeen;
    ULONGLONG lastAttempt;
    BOOL      injected;
    BOOL      waitReported;
} CANDIDATE;

#define MAX_CANDIDATES 32
#define CHILD_MIN_AGE_MS   3000
#define SUSPENDED_CHILD_GRACE_MS 50
#define RETRY_INTERVAL_MS  2000

int main(int argc, char** argv) {
    char targetExe[MAX_PATH] = "hololive-Dreams.exe";
    char configuredDllPath[MAX_PATH];
    char absoluteDllPath[MAX_PATH];
    DWORD length;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC wineVersion = ntdll
        ? GetProcAddress(ntdll, "wine_get_version")
        : NULL;

    length = GetEnvironmentVariableA(
        "HOLO_EMU_TARGET", targetExe, ARRAYSIZE(targetExe));
    if (length >= ARRAYSIZE(targetExe))
        strcpy_s(targetExe, ARRAYSIZE(targetExe),
                 "hololive-Dreams.exe");

    length = GetEnvironmentVariableA(
        "HOLO_EMU_DLL", configuredDllPath,
        ARRAYSIZE(configuredDllPath));
    if (length && length < ARRAYSIZE(configuredDllPath)) {
        if (!GetFullPathNameA(
                configuredDllPath, ARRAYSIZE(absoluteDllPath),
                absoluteDllPath, NULL)) {
            printf("[-] Could not resolve HOLO_EMU_DLL=\"%s\".\n",
                   configuredDllPath);
            return 1;
        }
    } else {
        char* slash;
        length = GetModuleFileNameA(
            NULL, absoluteDllPath, ARRAYSIZE(absoluteDllPath));
        if (!length || length >= ARRAYSIZE(absoluteDllPath)) {
            printf("[-] Could not determine loader.exe's directory.\n");
            return 1;
        }
        slash = strrchr(absoluteDllPath, '\\');
        if (!slash) slash = strrchr(absoluteDllPath, '/');
        if (!slash) {
            printf("[-] loader.exe has no resolvable parent directory.\n");
            return 1;
        }
        strcpy_s(slash + 1,
                 ARRAYSIZE(absoluteDllPath) -
                     (SIZE_T)(slash + 1 - absoluteDllPath),
                 "Emulator.dll");
    }

    if (GetFileAttributesA(absoluteDllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Emulator.dll was not found at %s\n",
               absoluteDllPath);
        return 1;
    }

    if (argc > 1 &&
        (_stricmp(argv[1], "--check") == 0 ||
         _stricmp(argv[1], "-c") == 0)) {
        printf("[+] Configuration check passed.\n");
        printf("[+] Runtime: %s\n",
               wineVersion ? "Wine/Proton" : "Windows");
        printf("[+] Target: %s\n", targetExe);
        printf("[+] Emulator: %s\n", absoluteDllPath);
        return 0;
    }

    printf("[*] Continuously hunting for %s...\n", targetExe);
    printf("[*] Runtime: %s\n",
           wineVersion ? "Wine/Proton" : "Windows");
    printf("[*] Emulator: %s\n", absoluteDllPath);
    printf("[*] (Press Ctrl+C to stop)\n\n");

    CANDIDATE cands[MAX_CANDIDATES] = {0};
    int candCount = 0;

    while (1) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) { Sleep(50); continue; }

        ULONGLONG now = GetTickCount64();
        BOOL seen[MAX_CANDIDATES] = {0};

        if (Process32First(hSnap, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, targetExe) != 0) continue;

                int idx = -1;
                for (int i = 0; i < candCount; i++) {
                    if (cands[i].pid == pe32.th32ProcessID) { idx = i; break; }
                }
                if (idx < 0 && candCount < MAX_CANDIDATES) {
                    unsigned generation = 0;
                    for (int i = 0; i < candCount; i++) {
                        if (cands[i].pid == pe32.th32ParentProcessID) {
                            generation = cands[i].generation + 1;
                            break;
                        }
                    }
                    idx = candCount++;
                    cands[idx].pid         = pe32.th32ProcessID;
                    cands[idx].parentPid   = pe32.th32ParentProcessID;
                    cands[idx].generation  = generation;
                    cands[idx].firstSeen   = now;
                    cands[idx].lastAttempt = 0;
                    cands[idx].injected    = FALSE;
                    cands[idx].waitReported = FALSE;
                    printf("[+] Found %s! PID: %d (parent PID: %d, "
                           "generation: %u)\n", targetExe,
                           pe32.th32ProcessID, pe32.th32ParentProcessID,
                           generation);
                }
                if (idx < 0 || cands[idx].injected) continue;
                seen[idx] = TRUE;

                BOOL parentIsGame = FALSE;
                for (int i = 0; i < candCount; i++) {
                    if (cands[i].pid == cands[idx].parentPid) { parentIsGame = TRUE; break; }
                }

                if (parentIsGame && cands[idx].generation < 2) {
                    ULONGLONG age = now - cands[idx].firstSeen;
                    BOOL stateKnown = FALSE;
                    BOOL suspended = IsProcessSuspended(cands[idx].pid,
                                                        &stateKnown);
                    if (stateKnown && suspended &&
                        age < SUSPENDED_CHILD_GRACE_MS) {
                        if (!cands[idx].waitReported) {
                            printf("[*] PID %d is suspended; allowing up to "
                                   "%d ms for hollowing before pre-release "
                                   "injection.\n", cands[idx].pid,
                                   SUSPENDED_CHILD_GRACE_MS);
                            cands[idx].waitReported = TRUE;
                        }
                        continue;
                    }
                    if (stateKnown && suspended) {
                        printf("[*] PID %d remained suspended past the "
                               "hollowing grace period; injecting before "
                               "release.\n", cands[idx].pid);
                    }
                    if (!stateKnown && age < CHILD_MIN_AGE_MS) continue;

                    if (stateKnown && age < CHILD_MIN_AGE_MS) {
                        printf("[*] PID %d is already running; bypassing the "
                               "slow child fallback.\n", cands[idx].pid);
                    }
                } else if (parentIsGame) {
                    printf("[*] PID %d is final-stage generation %u; "
                           "injecting immediately.\n",
                           cands[idx].pid, cands[idx].generation);
                }

                if (now - cands[idx].lastAttempt < RETRY_INTERVAL_MS) continue;
                cands[idx].lastAttempt = now;

                {
                    ULONG_PTR emulatorBase =
                        FindEmulatorBase(cands[idx].pid);
                    if (emulatorBase &&
                        IsEmulatorReady(
                            cands[idx].pid,
                            emulatorBase,
                            absoluteDllPath)) {
                        printf("[+] Emulator.dll is initialized in PID %d "
                               "(ready cookie verified).\n\n",
                               cands[idx].pid);
                        cands[idx].injected = TRUE;
                        continue;
                    }
                    if (emulatorBase) {
                        printf("[*] Emulator.dll is visible but not initialized "
                               "in PID %d; synchronizing through LoadLibrary.\n",
                               cands[idx].pid);
                    }
                }

                printf("[*] Injecting %s into PID %d...\n", absoluteDllPath, cands[idx].pid);
                if (InjectDLL(cands[idx].pid, absoluteDllPath)) {
                    printf("[+] Injection successful!\n\n");
                    cands[idx].injected = TRUE;
                } else {
                    printf("[-] Injection failed (will retry).\n\n");
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);

        for (int i = 0; i < candCount; i++) {
            if (cands[i].injected || seen[i]) {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, cands[i].pid);
                if (!h) {
                    cands[i] = cands[candCount - 1];
                    candCount--;
                    i--;
                } else {
                    CloseHandle(h);
                }
            }
        }

        Sleep(1);
    }

    return 0;
}
