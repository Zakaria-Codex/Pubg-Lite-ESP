#include <stdio.h>
#include <Windows.h>
#include <winioctl.h>
#include <string>
#include <Winternl.h>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <algorithm>
#include <tlhelp32.h>
#include <tchar.h>

#include <vector>

#pragma comment(lib, "ntdll.lib")


#pragma warning(disable: 4996)
#define IOCTL_READ_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x999, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x998, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_BASE_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x997, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ModuleBase_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x996, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DRIVER_NAME L"\\\\.\\GXONE"

EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);

#pragma comment(lib, "MoaRpm.lib")
class othermem
{
public:
	static int GetProcessThreadNumByID(DWORD dwPID)
	{
		//获取进程信息
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return 0;

		PROCESSENTRY32 pe32 = { 0 };
		pe32.dwSize = sizeof(pe32);
		BOOL bRet = ::Process32First(hProcessSnap, &pe32);;
		while (bRet)
		{
			if (pe32.th32ProcessID == dwPID)
			{
				::CloseHandle(hProcessSnap);
				return pe32.cntThreads;
			}
			bRet = ::Process32Next(hProcessSnap, &pe32);
		}
		return 0;
	}
	static int getAowProcID() {
		DWORD dwRet = 0;
		DWORD dwThreadCountMax = 0;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		Process32First(hSnapshot, &pe32);
		do
		{
			if (_tcsicmp(pe32.szExeFile, _T("VALORANT-Win64-Shipping.exe")) == 0)

			{
				DWORD dwTmpThreadCount = GetProcessThreadNumByID(pe32.th32ProcessID);

				if (dwTmpThreadCount > dwThreadCountMax)
				{
					dwThreadCountMax = dwTmpThreadCount;
					dwRet = pe32.th32ProcessID;
				}
			}
		} while (Process32Next(hSnapshot, &pe32));
		CloseHandle(hSnapshot);
		return dwRet;
	}
	static int GetProcessIdByName(LPCTSTR szProcess)//注意要加exe后缀
	{
		int dwRet = -1;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		Process32First(hSnapshot, &pe32);
		do
		{
			if (_tcsicmp(pe32.szExeFile, szProcess) == 0)
			{
				dwRet = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
		CloseHandle(hSnapshot);
		return dwRet;
	}
	static	DWORD FindProcessId(const std::string& processName)
	{
		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == INVALID_HANDLE_VALUE) {
			return 0;
		}

		Process32First(processesSnapshot, &processInfo);
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}

		while (Process32Next(processesSnapshot, &processInfo))
		{
			if (!processName.compare(processInfo.szExeFile))
			{
				CloseHandle(processesSnapshot);
				return processInfo.th32ProcessID;
			}
		}

		CloseHandle(processesSnapshot);
		return 0;
	}
	static void killProcessByName(LPCSTR name)
	{
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		PROCESSENTRY32 pEntry;
		pEntry.dwSize = sizeof(pEntry);
		BOOL hRes = Process32First(hSnapShot, &pEntry);
		while (hRes)
		{
			if (_tcsicmp(pEntry.szExeFile, name) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
					(DWORD)pEntry.th32ProcessID);
				if (hProcess != NULL)
				{
					TerminateProcess(hProcess, 9);
					CloseHandle(hProcess);
				}
			}
			hRes = Process32Next(hSnapShot, &pEntry);
		}
		CloseHandle(hSnapShot);
	}
private:

};
class MoaRpm {
public:
	static enum MOA_MODE {
		STANDARD,
		NTDLL,
		KERNEL
	};
private:
	DWORD pID;
	HANDLE hProcess;
	MOA_MODE mode = MOA_MODE::STANDARD;
	BOOL load_driver(std::string TargetDriver, std::string TargetServiceName, std::string TargetServiceDesc);

	BOOL delete_service(std::string TargetServiceName);
	std::string exePath();
	bool isElevated();

	bool isTestMode();
	const static unsigned char rawDriver[8304];
	void init(DWORD pID, MOA_MODE AccessMode);
	int MemFind(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen);
	int SundaySearch(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize);
	typedef struct _MEMORY_REGION
	{
		DWORD_PTR dwBaseAddr;
		DWORD_PTR dwMemorySize;
	}MEMORY_REGION;
	typedef struct info_t {
		HANDLE pid;
		PVOID SourceAddress;
		PVOID TargetAddress;
		SIZE_T Size;
		PVOID Base;
		char* m_pModName;
		ULONGLONG m_ulModBase;

		//string shit
		void* bufferAddress;
	}info, * p_info;
public:
	MoaRpm(DWORD pID, MOA_MODE AccessMode);
	MoaRpm(const char* windowname, MOA_MODE AccessMode);
	~MoaRpm();
	void readRaw(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
	bool writeRaw(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
	bool IsValid(DWORD_PTR Address);
	DWORD_PTR ModuleBase(std::string moduleToFind);
	DWORD_PTR KGetImageBase();
	DWORD_PTR KModuleHandle(char* moduleToFind);
	BOOL MemSearch(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet);
	template <class cData>
	cData read(DWORD_PTR Address);

	template <class cData>
	bool write(DWORD_PTR Address, cData buffer);

	template<class CharT = char>
	std::basic_string<CharT> readString(DWORD_PTR address, size_t max_length = 256);
};

template <class cData>
cData MoaRpm::read(DWORD_PTR Address) {
	cData B;
	SIZE_T bytesRead;
	this->readRaw((LPCVOID)Address, &B, sizeof(B), &bytesRead);
	return B;
}

template <class cData>
bool MoaRpm::write(DWORD_PTR Address, cData buffer) {
	SIZE_T bytesRead;
	this->writeRaw((LPCVOID)Address, &buffer, sizeof(cData), &bytesRead);
	return true;
}

template<class CharT>
std::basic_string<CharT> MoaRpm::readString(DWORD_PTR address, size_t max_length)
{
	std::basic_string<CharT> str(max_length, CharT());
	SIZE_T bytesRead;
	this->readRaw((LPVOID)address, &str[0], sizeof(CharT) * max_length, &bytesRead);
	auto it = str.find(CharT());
	if (it == str.npos) str.clear();
	else str.resize(it);
	return str;
}