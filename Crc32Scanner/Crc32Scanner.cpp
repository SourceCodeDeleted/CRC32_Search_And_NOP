#include "includes.h"

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


HANDLE Cr32Scanner::LaunchSuspendedProcess(char* cmd, PHANDLE ptr_thread) // cleaned up a bit, but no RAII
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

void Cr32Scanner::EnableDebugPriv()
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





void Cr32Scanner::GetVirtuInfo(HANDLE hprocess)
{
    MEMORY_BASIC_INFORMATION mbi;    
    unsigned char* addr = 0;

    while (VirtualQueryEx(hprocess, addr, &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD)
        {
            this->InsertNodeAtLastPosition(&this->s_vmap, (uintptr_t)mbi.BaseAddress, (uintptr_t)mbi.BaseAddress + mbi.RegionSize, mbi.RegionSize);
        }
        addr += mbi.RegionSize;
    }
    //this->printList(this->s_vmap);
}

//F2 ?? 0F38F1 ?? ??
//F2 48 0F38F1 1C C2
//F2 49 0F38F1 04 C8
//F2 49 0F38F1 0C C0
//F2 48 0F38F1 3C C6
//F2 48 0F38F1 34 C7
//F2 48 0F38F1 3C C3
//F2 48 0F38F1 1C C7

bool found = false;
int main(int argc, char** argv){

    for (;;)
    {
        switch (getopt(argc, argv, "f:p:n:s:h")) // note the colon (:) to indicate that 'b' has a parameter and is not a switch
        {
        case 'f':
            printf("switch '--file' specified\n");
            continue;   

        case 'p':
            printf("parameter '--printMM' specified with the value %s\n", optarg);
            continue;

        case 'n':
            printf("parameter '--nop' specified with the value %s\n", optarg);
            continue;

        case 's':
            printf("parameter '--search' specified with the value %s\n", optarg);
            continue;

        case '?':
        case 'h':
        default:
            printf("Help/Usage Example\n");
            break;

        case -1:
            break;
        }

        break;
    }
   




    std::shared_ptr <Cr32Scanner>  p_cr32scanner(new Cr32Scanner());   

    crc32Values s_crc32values = { 0xF2, 0x48, 0x49, 0x0F, 0x38, 0xF1, 0x1C, 0xC2 };

    // maybe maybe maybe one day I will set this for 32 bit.
    bool Is64Bit = false;

    // set current process with admin token
    p_cr32scanner->EnableDebugPriv();

    char cmd[] = "C:\\Users\\krash\\Desktop\\Testremmy_patched.exe";  // #notepad.exe"; // note: non-const (writeable array)
    HANDLE thread = nullptr;
    unsigned char* addr = 0;
      
    std::cout << "Creating Process for " << cmd << std::endl;
    HANDLE hprocess = p_cr32scanner->LaunchSuspendedProcess(cmd, std::addressof(thread));

    // Unfortunatelly casting to char didn't always work for some reason.
    int64_t mask = 0x00000000000000ff;

    p_cr32scanner->GetVirtuInfo(hprocess);
    if (hprocess)
    {
        //GET NEXT blocks
        VirtualAddressMap::vmap *currentNode = p_cr32scanner->s_vmap;

        while(currentNode != nullptr){
            long long StartAddress   = currentNode->StartAddress;
            long long EndAddress     = currentNode->EndAddress;
            size_t MemBlockSize      = currentNode->RegionSize;

            // CHECK BLOCK SIZES
            char* Buffer = new char[MemBlockSize + 20];
            memset(&Buffer[0], 0,  MemBlockSize  + 20);

            if (!ReadProcessMemory(hprocess, (LPVOID)(StartAddress), Buffer, MemBlockSize, nullptr))
                {
                        printf("[-] Error Occured - Failed to Read Memory. At Address -- 0x%llx 0x%08X \n", StartAddress, GetLastError());
                        currentNode = currentNode->Next;
                        continue;
                }

            for (unsigned int i = 0; i < MemBlockSize; i++) {
                if ((Buffer[i + 0] & mask)  == s_crc32values.first) {
                if ((Buffer[i + 1] & mask)  == s_crc32values.skip || (Buffer[i + 1] & mask) == s_crc32values.skip2) {
                if ((Buffer[i + 2] & mask)  == s_crc32values.third1) {
                if ((Buffer[i + 3] & mask)  == s_crc32values.third2) {
                if ((Buffer[i + 4] & mask)  == s_crc32values.third3) {
                printf("CRC32 Found! at 0x%llx\n", StartAddress + i);
                                }
                            }
                        }
                    }
                }
            }

            currentNode = currentNode->Next;
            delete[] Buffer;
        }

        std::cout << "press enter to resume process... " && std::cin.get();
              ResumeThread(thread);
              CloseHandle(thread);
              CloseHandle(hprocess);
    }
}