#pragma once


class Cr32Scanner : public VirtualAddressMap 
{

public:
	void EnableDebugPriv();
	void GetVirtuInfo(HANDLE hprocess);
	HANDLE LaunchSuspendedProcess(char* cmd, PHANDLE ptr_thread);
	HANDLE TakeSnapShot(const wchar_t* processName);
	bool IfFileExists(const std::string& fileName);
	

	void setFileName(std::string fileName);
	void setIgnoreBlocks(std::vector<std::string> ignoreBlocks);
	void setPrintMemoryMap(bool printMemoryMap);
	void setSearchOnly(bool searchOnly);
	void setNopAllowed(bool nopAllowed);

	std::string getFileName();
	std::string getIgnoreBlocks();
	bool getPrintMemoryMap();
	bool getSearchOnly();
	bool getNopAllowed();


	vmap *s_vmap = nullptr;
private:
	std::string FileName;
	std::string IgnoreBlocks;
	bool PrintMemoryMap;
	bool SearchOnly;
	bool NopAllowed;


};
