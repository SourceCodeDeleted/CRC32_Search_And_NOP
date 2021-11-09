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
    return std::filesystem::exists(fileName);
}

void Cr32Scanner::setFileName(std::string fileName)         { this->FileName = fileName; }
void Cr32Scanner::setIgnoreBlocks(std::vector<std::string> ignoreBlocks) { this->IgnoreBlocks = ignoreBlocks; }
void Cr32Scanner::setPrintMemoryMap(bool printMemoryMap)    { this->PrintMemoryMap = printMemoryMap; }
void Cr32Scanner::setKeepProcessSuspended(bool suspend)     { this->KeepSuspended = suspend; }
void Cr32Scanner::setSearchOnly(bool searchOnly)            { this->SearchOnly = searchOnly; }
void Cr32Scanner::setNopAllowed(bool nopAllowed)            { this->NopAllowed = nopAllowed; }
void Cr32Scanner::setPrintLocation(bool printLocation)      { this->PrintLocation = printLocation; }


std::string Cr32Scanner::getFileName() { return this->FileName; }
std::vector<std::string> Cr32Scanner::getIgnoreBlocks() { return this->IgnoreBlocks; }
bool Cr32Scanner::getPrintMemoryMap() { return this->PrintMemoryMap; }
bool Cr32Scanner::getKeepProcessSuspended() { return this->KeepSuspended; }
bool Cr32Scanner::getSearchOnly() { return this->SearchOnly; }
bool Cr32Scanner::getNopAllowed() { return this->NopAllowed; }
bool Cr32Scanner::getPrintLocation() { return this->PrintLocation; }


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
    if (this->getPrintMemoryMap()) {
        this->printList(this->s_vmap);
    }
}

size_t Cr32Scanner::NopCR32(HANDLE hprocess, LPVOID address, int bytesCount)
{
        char NOP[] = "\x90\x90\x90\x90\x90\x90\x90\x90";
        size_t bytes_written = 0;
        if (!WriteProcessMemory(hprocess, address, (LPCVOID)NOP, bytesCount, &bytes_written)) {
            std::cout << "[+] Error Writing to Location " << std::hex << address << std::endl;
        }
        return bytes_written;
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
        ("p,printmm", "Print MemoryMap",               cxxopts::value<bool>()->default_value("true"))
        ("n,nop",     "When a search matches, NOP it", cxxopts::value<bool>()->default_value("true"))
        ("l,locate",  "Prints Address of CR32",        cxxopts::value<bool>()->default_value("true"))
        ("k,keepsuspended", "Keep process suspended",  cxxopts::value<bool>()->default_value("true"))
        ("i,ignore",  "Memory blocks to ignore",       cxxopts::value<std::vector<std::string>>())
        ("h,help",    "\n\nUsage:"
          "--file=/path/to/my/file.exe --locate --nop --ignore 0x000007ff4567845ff,0x000007ff4567845ff # will launch the file, NOP all CRC32 Addresses skipping the search in those blocks\n"
          "--file=/path/to/my/file.exe --printmm # prints memory blocks \n"
          "--file=/path/to/my/file.exe --nop -k #search all blocks and NOP all Crc32s Found , but leave process suspended\n"
            "");

    auto result = options.parse(argc, argv);
    if (result.count("help"))
    {
        std::cout << options.help() << std::endl;
        exit(0);
    }
    if (result.count("file")) {
        if (p_cr32scanner->IfFileExists(result["file"].as<std::string>())) {
            p_cr32scanner->setFileName( result["file"].as<std::string>());
        }
    }
        else {
            std::cout << "[-] Error File Not Found. Aborting\n";
            abort();
        }
    if (result.count("nop"))
        p_cr32scanner->setNopAllowed(result["nop"].as<bool>());
    if (result.count("locate"))
        p_cr32scanner->setPrintLocation(result["locate"].as<bool>());
    if (result.count("printmm"))
        p_cr32scanner->setPrintMemoryMap(result["printmm"].as<bool>());
    if (result.count("keepsuspended"))
        p_cr32scanner->setKeepProcessSuspended(result["keepsuspended"].as<bool>());
    if (result.count("ignore"))
        p_cr32scanner->setIgnoreBlocks(result["ignore"].as<std::vector<std::string>>());

              
    crc32Values s_crc32values = { 0xF2, 0x48, 0x49, 0x0F, 0x38, 0xF1, 0x1C, 0xC2 };

    // maybe maybe maybe one day I will set this for 32 bit.
    bool Is64Bit = true;

    // set current process with admin token
    p_cr32scanner->EnableDebugPriv();
  

    // Why is this leading to dangling pointer?
    // but the latter is ok?
    // const char* cmd = p_cr32scanner->getFileName().c_str();

    std::string strcmd = p_cr32scanner->getFileName();
    const char* cmd = strcmd.c_str();

    HANDLE thread = nullptr;
    unsigned char* addr = 0;
      
    std::cout << "Creating Process for " << cmd << std::endl;
    HANDLE hprocess = p_cr32scanner->LaunchSuspendedProcess((char *)cmd, std::addressof(thread));

    // Unfortunatelly casting to char didn't always work for some reason.
    // Technically a 32 bit mask should work in all scenarios.
        int64_t mask = 0x00000000000000ff;
        int ArchLength = 0;

    if (Is64Bit) {
        int64_t mask = 0x00000000000000ff;
        ArchLength = 8;
    }
    else {
        int32_t mask = 0x000000FF;
        ArchLength = 4;
    }

    p_cr32scanner->GetVirtuInfo(hprocess);

    std::vector<std::string> vtemp = p_cr32scanner->getIgnoreBlocks();

    // if we have any ignore blocks in our vector
    if (!vtemp.empty()) {
        for (int i = 0; i < vtemp.size(); i++) {
           long long tempStartAddress = p_cr32scanner->ConvertStrAddressToInt((char *)vtemp[i].c_str());
           p_cr32scanner->DeleteNodeByKey(&p_cr32scanner->s_vmap, tempStartAddress);
        }
    }




    if (hprocess)
    {

        VirtualAddressMap::vmap *currentNode = p_cr32scanner->s_vmap;
        
        if (p_cr32scanner->getPrintLocation()) {
            
            while (currentNode != nullptr) {
                long long StartAddress = currentNode->StartAddress;
                long long EndAddress = currentNode->EndAddress;
                size_t MemBlockSize = currentNode->RegionSize;

                // CHECK BLOCK SIZES
                char* Buffer = new char[MemBlockSize + 20];
                memset(&Buffer[0], 0, MemBlockSize + 20);

                if (!ReadProcessMemory(hprocess, (LPVOID)(StartAddress), Buffer, MemBlockSize, nullptr))
                {
                    printf("[-] Error Occured - Failed to Read Memory. At Address -- 0x%llx 0x%08X \n", StartAddress, GetLastError());
                    currentNode = currentNode->Next;
                    continue;
                }

                for (unsigned int i = 0; i < MemBlockSize; i++) {
                if ((Buffer[i + 0] & mask) == s_crc32values.first) {
                if ((Buffer[i + 1] & mask) == s_crc32values.skip   || (Buffer[i + 1] & mask) == s_crc32values.skip2) {
                if ((Buffer[i + 2] & mask) == s_crc32values.third1) {
                if ((Buffer[i + 3] & mask) == s_crc32values.third2) {
                if ((Buffer[i + 4] & mask) == s_crc32values.third3) {
                            
                            if (p_cr32scanner->getNopAllowed()) {
                                long long PatchAddress = StartAddress + i;
                                std::cout << "[+]CRC32 Found! -  NOP Allowed, Writing to \t" << std::hex << StartAddress + i << std::endl;
                                p_cr32scanner->NopCR32(hprocess, (LPVOID)PatchAddress, ArchLength);
                            }
                            else {
                                printf("[+] CRC32 Found! at \t 0x%llx\n", StartAddress + i);
                            }
                                    }
                                }
                            }
                        }
                    }
                }

                currentNode = currentNode->Next;
                delete[] Buffer;
            }
        }
        if (p_cr32scanner->getKeepProcessSuspended()) {
            std::cout << "press enter to resume process... " && std::cin.get();
            ResumeThread(thread);
            CloseHandle(thread);
            CloseHandle(hprocess);
            
        }
        else {
            ResumeThread(thread);
            CloseHandle(thread);
            CloseHandle(hprocess);
            
        }
              
    }
}