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


bool Cr32Scanner::IfFileExists(const std::string& fileName)
{
    // do I really not have C++17?
    struct stat buffer;
    return (stat(fileName.c_str(), &buffer) == 0);
}

void Cr32Scanner::setFileName(std::string fileName)         { this->FileName = fileName; }
void Cr32Scanner::setIgnoreBlocks(std::vector<std::string> ignoreBlocks) {  }
void Cr32Scanner::setPrintMemoryMap(bool printMemoryMap)    { this->PrintMemoryMap = printMemoryMap; }
void Cr32Scanner::setSearchOnly(bool searchOnly)            { this->SearchOnly = searchOnly; }
void Cr32Scanner::setNopAllowed(bool nopAllowed)            { this->NopAllowed = nopAllowed; }

std::string Cr32Scanner::getFileName() { return this->FileName; }
std::string Cr32Scanner::getIgnoreBlocks() { return this->IgnoreBlocks; }
bool Cr32Scanner::getPrintMemoryMap() { return this->PrintMemoryMap; }
bool Cr32Scanner::getSearchOnly() { return this->SearchOnly; }
bool Cr32Scanner::getNopAllowed() { return this->NopAllowed; }


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

    std::shared_ptr <Cr32Scanner>  p_cr32scanner(new Cr32Scanner());

    cxxopts::Options options("Crc32 Search And Nop", "I search for your CRC32 opcodes and Nop them...");
    


    options.add_options()
        ("f,file",    "Specify --File= to load",       cxxopts::value<std::string>())
        ("p,printmm", "Print MemoryMap",               cxxopts::value<bool>()->default_value("false"))
        ("n,nop",     "When a search matches, NOP it", cxxopts::value<bool>()->default_value("false"))
        ("i,ignore",  "Memory blocks to ignore",       cxxopts::value<std::vector<std::string>>())
        // Add Search only option?
        ("h,help",    "\n\nUsage:"
          "--file=/path/to/my/file.exe --nop --ignore 0x000007ff4567845ff,0x000007ff4567845ff # will launch the file, NOP all cr32 addrs skipping the search in those blocks\n"
          "--file=/path/to/my/file.exe --printmm # prints memory blocks \n"
          "--file=/path/to/my/file.exe --nop search all blocks and NOP all Crc32s Found\n"
            "");

    auto result = options.parse(argc, argv);
    if (result.count("help"))
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }
    if (result.count("file"))
        if (p_cr32scanner->IfFileExists(result["file"].as<std::string>())) {
            p_cr32scanner->setFileName(result["file"].as<std::string>());
        }
        else {
            std::cout << "[-] Error File Not Found. Aborting\n";
            abort();
        }
    if (result.count("nop"))
        p_cr32scanner->setNopAllowed(result["nop"].as<bool>());
    if (result.count("printmm"))
        p_cr32scanner->setPrintMemoryMap(result["printmm"].as<bool>());
    if (result.count("ignore"))
        p_cr32scanner->setIgnoreBlocks( result["ignore"].as<std::vector<std::string>>() );
        //p_cr32scanner->setSearchOnly
        //result["file"].as<std::string>()
      
    std::cout << p_cr32scanner->getFileName().c_str();
        
    crc32Values s_crc32values = { 0xF2, 0x48, 0x49, 0x0F, 0x38, 0xF1, 0x1C, 0xC2 };

    // maybe maybe maybe one day I will set this for 32 bit.
    bool Is64Bit = true;

    // set current process with admin token
    p_cr32scanner->EnableDebugPriv();

    char cmd[] = "C:\\Users\\krash\\Desktop\\Testremmy_patched.exe";  // #notepad.exe"; // note: non-const (writeable array)
  
    //const char* cmd = p_cr32scanner->getFileName().c_str();
    HANDLE thread = nullptr;
    unsigned char* addr = 0;
      
    std::cout << "Creating Process for " << cmd << std::endl;
    HANDLE hprocess = p_cr32scanner->LaunchSuspendedProcess((char *)cmd, std::addressof(thread));

    // Unfortunatelly casting to char didn't always work for some reason.
        int64_t mask = 0x00000000000000ff;

    if (Is64Bit) {
        int64_t mask = 0x00000000000000ff;
    }
    else {
        int32_t mask = 0x000000FF;
    }

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