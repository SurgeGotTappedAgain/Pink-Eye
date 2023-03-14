#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define POOLTAG 'EB'

typedef unsigned long long QWORD;
#define ABSOLUTE(wait)			(wait)
#define RELATIVE(wait)			(-(wait))
#define NANOSECONDS(nanos)		(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)	(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)		(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)		(((signed __int64)(seconds)) * MILLISECONDS(1000L))

namespace Utils
{
    PVOID GetSystemRoutineAddress(LPCWSTR name)
    {
        UNICODE_STRING unicodeName;
        RtlInitUnicodeString(&unicodeName, name);
        return MmGetSystemRoutineAddress(&unicodeName);
    }

    PVOID GetSystemModuleBase(LPCWSTR name)
    {
        PLIST_ENTRY loadedModuleList = (PLIST_ENTRY)(GetSystemRoutineAddress(L"PsLoadedModuleList"));
        if (!loadedModuleList)
        {
            return NULL;
        }
        __try
        {
            for (PLIST_ENTRY link = loadedModuleList->Flink; link != loadedModuleList; link = link->Flink)
            {
                LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (_wcsicmp(name, entry->BaseDllName.Buffer) == 0)
                {
                    return entry->DllBase;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return NULL;
        }
        return NULL;
    }

    void WriteProtectOff()
    {
        auto cr0 = __readcr0();
        cr0 &= 0xfffffffffffeffff;
        __writecr0(cr0);
        _disable();
    }

    void WriteProtectOn()
    {
        auto cr0 = __readcr0();
        cr0 |= 0x10000;
        _enable();
        __writecr0(cr0);
    }

    bool is_pg_protected(const char* image)
    {
        static CONST CHAR* images[] = { "win32kbase.sys", "tm.sys", "clfs.sys", "msrpc.sys", "ndis.sys", "ntfs.sys", "fltmgr.sys", "clipsp.sys", "cng.sys", "Wdf01000.sys", "WppRecorder.sys", "SleepStudyHelper.sys", "acpiex.sys", "ACPI.sys", "pci.sys", "tpm.sys", "intelpep.sys", "WindowsTrustedRT.sys", "pdc.sys", "CEA.sys", "partmgr.sys", "spaceport.sys", "volmgr.sys", "volmgrx.sys", "mountmgr.sys", "storahci.sys", "storport.sys", "hall.dll", "kd.dll", "ksecdd.sys", "stornvme.sys", "EhStorClass.sys", "fileinfo.sys", "Wof.sys", "Ntfs.sys", "ksecpkg.sys", "tcpip.sys", "fwpkclnt.sys", "wfplwfs.sys", "fvevol.sys", "volsnap.sys", "rdyboost.sys", "mup.sys" };
        for (INT i = 0; i < 43; ++i)
        {
            if (strstr(image, images[i]))
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    PVOID GetDriverBase(LPCSTR module_name)
    {
        ULONG bytes{};
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);
        if (!bytes)
        {
            return NULL;
        }
        PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOLTAG);
        if (modules)
        {
            status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(modules, POOLTAG);
                return NULL;
            }
            PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
            PVOID module_base{}, module_size{};
            for (ULONG i = 0; i < modules->NumberOfModules; i++)
            {
                if (strcmp(reinterpret_cast<char*>(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
                {
                    module_base = module[i].ImageBase;
                    module_size = (PVOID)module[i].ImageSize;
                    break;
                }
            }
            ExFreePoolWithTag(modules, POOLTAG);
            return module_base;
        }
        return NULL;
    }

    PVOID IATHook(PVOID lpBaseAddress, CHAR* lpcStrImport, PVOID lpFuncAddress)
    {
        PIMAGE_DOS_HEADER dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(lpBaseAddress) + dosHeaders->e_lfanew);
        IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + (DWORD_PTR)lpBaseAddress);

        LPCSTR libraryName = NULL;
        PVOID result = NULL;
        PIMAGE_IMPORT_BY_NAME functionName = NULL;

        if (!importDescriptor)
            return NULL;

        while (importDescriptor->Name != NULL)
        {
            libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)lpBaseAddress;
            if (GetDriverBase(libraryName))
            {
                PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
                originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + importDescriptor->OriginalFirstThunk);
                firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + importDescriptor->FirstThunk);
                while (originalFirstThunk->u1.AddressOfData != NULL)
                {
                    functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + originalFirstThunk->u1.AddressOfData);
                    if (strcmp(functionName->Name, lpcStrImport) == 0)
                    {
                        result = reinterpret_cast<PVOID>(firstThunk->u1.Function);
                        WriteProtectOff();
                        firstThunk->u1.Function = reinterpret_cast<ULONG64>(lpFuncAddress);
                        WriteProtectOn();
                        return result;
                    }
                    ++originalFirstThunk;
                    ++firstThunk;
                }
            }
            importDescriptor++;
        }
        return NULL;
    }

    static BOOLEAN is_retop(_In_ BYTE op)
    {
        return op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB;      
    }

    static QWORD find_codecave(_In_ VOID* module, _In_ INT length)
    {
        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
        IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);
        QWORD start = 0, size = 0;

        QWORD header_offset = (QWORD)IMAGE_FIRST_SECTION(nt_headers);
        for (INT x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
        {
            IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

            if (strcmp((CHAR*)header->Name, ".text") == 0)
            {
                start = (QWORD)module + header->PointerToRawData;
                size = header->SizeOfRawData;
                break;
            }
            header_offset += sizeof(IMAGE_SECTION_HEADER);
        }
        QWORD match = 0;
        INT curlength = 0;
        BOOLEAN ret = FALSE;

        for (QWORD cur = start; cur < start + size; ++cur)
        {
            if (!ret && is_retop(*(BYTE*)cur))
            {
                ret = TRUE;
            }
            else if (ret && *(BYTE*)cur == 0xCC)
            {
                if (!match) match = cur;
                if (++curlength == length) return match;
            }
            else
            {
                match = curlength = 0;
                ret = FALSE;
            }
        }
        return 0;
    }

    static BOOLEAN remap_page(_In_ VOID* address, _In_ BYTE* assembly, _In_ ULONG length, _In_ BOOLEAN restore)
    {
        MDL* mdl = IoAllocateMdl(address, length, FALSE, FALSE, 0);
        if (!mdl)
        {
            DbgPrint("[-] Failed allocating MDL!\n");
            return FALSE;
        }

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        VOID* map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
        if (!map_address)
        {
            DbgPrint("[-] Failed mapping the page!\n");
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
        if (status)
        {
            DbgPrint("[-] Failed MmProtectMdlSystemAddress with status: 0x%lX\n", status);
            MmUnmapLockedPages(map_address, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        RtlCopyMemory(map_address, assembly, length);

        if (restore)
        {
            status = MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
            if (status)
            {
                DbgPrint("[-] Failed second MmProtectMdlSystemAddress with status: 0x%lX\n", status);
                MmUnmapLockedPages(map_address, mdl);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                return FALSE;
            }
        }

        MmUnmapLockedPages(map_address, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        return TRUE;
    }

    static BOOLEAN patch_codecave_detour(_In_ QWORD address, _In_ QWORD target)
    {
        BYTE assembly[16] = 
        {
            0x50,                                                        // push rax
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
            0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
            0xC3                                                         // retn
        };
        *(QWORD*)(assembly + 3) = target;
        return remap_page((VOID*)address, assembly, 16, FALSE);
    }

    DWORD FindTextSection(char* module, DWORD* size)
    {
        PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
        {
            PIMAGE_SECTION_HEADER section = &sections[i];
            if (memcmp(section->Name, ".text", 5) == 0)
            {
                *size = section->Misc.VirtualSize;
                return section->VirtualAddress;
            }
        }
        return 0;
    }

    PRTL_PROCESS_MODULES GetModuleList()
    {
        ULONG length = 0;
        ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
        length += (10 * 1024);

        PRTL_PROCESS_MODULES module_list = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, length);
        ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length);

        if (!module_list)
        {
            DbgPrintEx(0, 0, "[-] Module List Is Empty\n");
            return 0;
        }
        return module_list;
    }

    VOID Sleep(LONGLONG milliseconds)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = RELATIVE(MILLISECONDS(milliseconds));
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    BOOLEAN WriteToReadOnlyMemory(IN VOID* destination, IN VOID* source, IN ULONG size)
    {
        PMDL mdl = IoAllocateMdl(destination, size, FALSE, FALSE, 0);
        if (!mdl)
            return FALSE;

        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        PVOID map_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, 0, FALSE, NormalPagePriority);
        if (!map_address)
        {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            MmUnmapLockedPages(map_address, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return FALSE;
        }

        RtlCopyMemory(map_address, source, size);

        MmUnmapLockedPages(map_address, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return TRUE;
    }

    VOID ToLower(IN CHAR* in, OUT CHAR* out)
    {
        INT i = -1;

        while (in[++i] != '\x00')
        {
            out[i] = (CHAR)tolower(in[i]);
        }
    }
}