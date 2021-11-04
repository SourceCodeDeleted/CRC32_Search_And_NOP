#pragma once


class Cr32Scanner : public VirtualAddressMap 
{

public:
	void EnableDebugPriv();
	void GetVirtuInfo(HANDLE hprocess);
	HANDLE LaunchSuspendedProcess(char* cmd, PHANDLE ptr_thread);
	HANDLE TakeSnapShot(const wchar_t* processName);



	vmap *s_vmap = nullptr;
private:
	std::string FileName;
	std::string IgnoreBlocks;
	bool PrintMemoryMap;
	bool SearchOnly;
	bool NopAllowed;


};
