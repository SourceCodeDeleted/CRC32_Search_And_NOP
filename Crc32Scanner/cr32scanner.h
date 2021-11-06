#pragma once

class Cr32Scanner : public VirtualAddressMap 
{

public:
	void EnableDebugPriv();
	void GetVirtuInfo(HANDLE hprocess);
	HANDLE LaunchSuspendedProcess(char* cmd, PHANDLE ptr_thread);
	HANDLE TakeSnapShot(const wchar_t* processName);
	bool IfFileExists(const std::string& fileName);
	size_t NopCR32(HANDLE hprocess, LPVOID address, int bytesCount);

	void setFileName(std::string fileName);
	void setIgnoreBlocks(std::vector<std::string> ignoreBlocks);
	void setPrintMemoryMap(bool printMemoryMap);
	void setSearchOnly(bool searchOnly);
	void setNopAllowed(bool nopAllowed);
	void setPrintLocation(bool printLocation);
	void setKeepProcessSuspended(bool suspend);

	std::string getFileName();
	std::vector<std::string> getIgnoreBlocks();

	bool getPrintMemoryMap();
	bool getPrintLocation();
	bool getSearchOnly();
	bool getNopAllowed();
	bool getKeepProcessSuspended();


	vmap *s_vmap = nullptr;


private:
	std::vector<std::string> IgnoreBlocks;
	std::string FileName;
	bool KeepSuspended  = false;
	bool PrintMemoryMap = false;
	bool SearchOnly     = false;
	bool NopAllowed     = false;
	bool PrintLocation  = false;


};
