// Crc32_Sanner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "includes.h"
#include <iostream>
#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <iomanip>
#include <inttypes.h>
#include <conio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>



HANDLE pHandle;


//F2 ?? 0F 38 F1 ??
// { 0xF2, 0x48, 0x49, 0x0F, 0x38, 0xF1, 0x1C, 0xC2 }
struct crc32Values {
    byte first;
    byte skip;
    byte skip2;

    byte third1;
    byte third2;
    byte third3;

    byte lastskip;
    byte lastskip2;
};







HANDLE LaunchSuspendedProcess(char* cmd, PHANDLE ptr_thread) // cleaned up a bit, but no RAII
{
    if (ptr_thread == nullptr) return nullptr;

    PROCESS_INFORMATION pi;
    STARTUPINFOA si{}; // initialize with zeroes.
    si.cb = sizeof(STARTUPINFOA);

    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, false, CREATE_SUSPENDED,
        nullptr, nullptr, std::addressof(si), std::addressof(pi)))
    {
        std::cerr << "CreateProcess failed, " << GetLastError() << '\n';
        *ptr_thread = nullptr;
        return nullptr;
    }

    *ptr_thread = pi.hThread;
    return pi.hProcess;
}

void PrintAddress(unsigned char* value)
{
    std::cout << std::hex << value << std::dec;
}

void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken);
}

void GetVirtuInfo(HANDLE hprocess)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = 0;

    

    while (VirtualQueryEx(hprocess, addr, &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD)
        {
            std::cout << "base : 0x" << std::hex << mbi.BaseAddress << " end : 0x" << std::hex << (uintptr_t)mbi.BaseAddress + mbi.RegionSize << "\n";
            //p_virtualaddressmap->InsertNodeAtLastPosition
        }
        addr += mbi.RegionSize;
    }


}



//Probably not needed/
// I don't like this . I would rather use something else.
HANDLE TakeSnapShot(const wchar_t* processName) {

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32); 
    MODULEENTRY32 me32 = MODULEENTRY32();
    me32.dwSize = sizeof(MODULEENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    
    
    if (Module32First(snapshot, &me32))
    {

        std::cout << reinterpret_cast<DWORD_PTR>(me32.modBaseAddr)  << me32.modBaseSize << std::endl;
        std::cout << me32.th32ModuleID << std::endl;
        std::cout << me32.szModule << std::endl;

        //std::cout << "name: " << me32.szModule;
        //printf("--- 0x%ll \n", me32.th32ModuleID);
       
    }
    else { std::cout << "[-] Error with Module32First"; }

    return 0;
}


//F2 ?? 0F 38 F1 ??
//F2 48 0F38F11CC2
//F2 49 0F38F1 04 C8
//F2 49 0F38F1 0C C0
//F2 48 0F38F1 3C C6
//F2 48 0F38F1 34 C7
//F2 48 0F38F1 3C C3
//F2 48 0F 38 F1 1C C7

bool found = false;
int main()
{
    MEMORY_BASIC_INFORMATION MemInfo;
    crc32Values s_crc32values = { 0xF2, 0x48, 0x49, 0x0F, 0x38, 0xF1, 0x1C, 0xC2 };
    bool Is64Bit = false;

    // set current process with admin token
    EnableDebugPriv();

    char cmd[] = "C:\\Users\\krash\\Desktop\\Testremmy_patched.exe";  // #notepad.exe"; // note: non-const (writeable array)
    HANDLE thread = nullptr;
    unsigned char* addr = 0;
      
    std::cout << "Creating Process for " << cmd << std::endl;
    HANDLE hprocess = LaunchSuspendedProcess(cmd, std::addressof(thread));
    //printf("%lu\n",hprocess);

    //HANDLE xprocess = TakeSnapShot(TEXT("Testremmy_patched.exe"));
    //printf("%lu\n", xprocess);

    //if (xprocess == hprocess) { printf("They match \n!"); exit(1); }

    GetVirtuInfo(hprocess);
    std::shared_ptr <VirtualAddressMap>  p_virtualaddressmap(new VirtualAddressMap());
    




    if (hprocess)
    {
        long long StartAddress = 0x7FF76Bffffff;    //0x7FF6D3813F1D;//0x7FF76Bffffff; //0x00007fffffffffff;
        long long EndAddress = 0x00;
        size_t MemBlockSize = 8;
        unsigned char Buffer[8] = { 0 };

       // auto* ptr = reinterpret_cast<unsigned char*>(&Buffer);

        for (StartAddress; StartAddress > EndAddress; StartAddress = StartAddress  - sizeof(char) ) {

            if (ReadProcessMemory(hprocess, (LPCVOID)(StartAddress), &Buffer, sizeof(long long), nullptr))
            {
                printf("[-] Error Occured - Failed to Read Memory. At Address -- 0x%llx 0x%08X \n", StartAddress, GetLastError());
                break;
            }

            for (unsigned int i = 0; i < sizeof(Buffer); i++) {
                printf("Address 0x%llx  %02X\n", StartAddress, Buffer[i]);

                if (Buffer[i] == s_crc32values.first) {
                    //printf("CRC32 START Found! at 0x%llx\n", StartAddress + i);
                    if (Buffer[i + 1] == s_crc32values.skip || Buffer[i + 1] == s_crc32values.skip2) {
                        if (Buffer[i + 2] == s_crc32values.third1) {
                            if (Buffer[i + 3] == s_crc32values.third2) {
                                if (Buffer[i + 4] == s_crc32values.third3) {
                                    printf("CRC32 Found! at 0x%llx\n", StartAddress + i);
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

      /*  for (StartAddress; StartAddress > EndAddress; StartAddress = StartAddress - (MemBlockSize - 1)) {
            if (ReadProcessMemory(xprocess, (void *)StartAddress, &Buffer, MemBlockSize, 0))
            {
                std::cout << "Error Occured - Failed to Read Memory.\n";
            }
            //printf("Address: \t\t  ByteBlock: \t\t  Sequence:     \n\n");
            if (!found) {
                printf("Address 0x%llx\n", StartAddress);

            }
            for (int i = 0; i < MemBlockSize; ++i) {
                //std::cout << std::hex << std::setfill('0') << Buffer[i] << ""; // EXTREMELY SLOW
                //if (i == MemBlockSize){printf("\n"); }
                   

                //check first byte
                if (Buffer[i] == s_crc32values.first) {
                    printf("CRC32 START Found! at 0x%llx\n", StartAddress + i);
                    if (Buffer[i + 1] == s_crc32values.skip || Buffer[i + 1] == s_crc32values.skip2) {
                        if (Buffer[i + 2] == s_crc32values.third1) {
                            if (Buffer[i + 3] == s_crc32values.third2) {
                                if (Buffer[i + 4] == s_crc32values.third3) {
                                    printf("CRC32 Found! at 0x%llx\n", StartAddress + i);
                                    found = true;
                                    break;
                                }
                            }
                        }

                    }

                }
            }
        }*/



        //WriteProcessMemory(pHandle, reinterpret_cast<void*>(address), &newi, (DWORD)sizeof(newi), 0)
        std::cout << "press enter to resume process... " && std::cin.get();
        /*      ResumeThread(thread);

              CloseHandle(thread);
              CloseHandle(hprocess);*/
    }





    //pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); 





}