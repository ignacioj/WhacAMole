#pragma once
#ifndef WhacAMole_H   
#define WhacAMole_H

#define _HAS_STD_BYTE 0

#include "stdafx.h"
#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <evntrace.h>


using namespace std;

#define IMAGE_FILE_MACHINE_i386 0x014c
#define IMAGE_FILE_MACHINE_IA64 0x0200
#define IMAGE_FILE_MACHINE_AMD64 0x8664

#define MEM_SIZE_SHOW 256
#define MEM_SIZE_SHOW_Zydif 32

string CalcSHA1(wstring fileName);
string CalcSHA1Buff(PVOID buffer, DWORD size, int& cuenta);
string CalcSHA256Buff(PVOID buffer, DWORD size);
vector<string> Get_TCP(DWORD buscadoPID); 
#endif
void GetMapHandles();
bool PrintHandles(DWORD pid, string& vCLR, string& vCLRFF, bool dumpProcess, vector<char>& memContent, DWORD64 base);
void HexDump(DWORD64 base, void* addr, int len, string colSpan, bool creaRow, bool outText, bool outHTML);
void CambiaColorTexto(char* texto, DWORD color);
void UseZydif(DWORD64 base, void* mem, int memsize, string colSpan, bool creaRow, bool outText, bool outHTML);

void __cdecl GetMemoryTasks();

int NetAssemblyInfo();
DWORD WINAPI IniTrace(LPVOID data);
static void NTAPI ProcessEvent(PEVENT_RECORD EventRecord);
DWORD Limpieza(TRACEHANDLE hTrace);

typedef struct _MEMORY_TASKS
{
	wstring taskName;
	wstring taskPath;
	wstring taskAction;
	wstring taskInstanceGuid;
}MEMORY_TASKS, * PMEMORY_TASKS;

typedef struct _SALIDA_MODULOS_EXTENDIDA
{
	string sha1Hash;
	bool unusualMod;
	bool wrongSizeOfInitializedData;
	bool peAnomalies;
	bool checkSumAlertis0;
	bool checkSumAlert;
	wstring modMemAllocProtect;
	wstring resType;
	bool signedPEnotMEMIMAGE;
	bool unsignedPEnotMEMIMAGE;
	bool nameHiddenMemory;
	bool dllHollowtxf;
	bool lagosIsland;
	bool mappedImage;
	bool phantomDllHollow;
	bool originalFileNameAlert;
	bool mismatchingPathAlert;
	bool dllHidingAlert;
} SALIDA_MODULOS_EXTENDIDA;

typedef struct _THREAD_SCANMEMORY_PARAMS
{
	HANDLE hProcess;
	DWORD processID;
	uint64_t inicioScan;
	uint64_t finScan;
} THREAD_SCANMEMORY_PARAMS, * PTHREAD_SCANMEMORY_PARAMS;

typedef struct PID_NAME_PPID
{
	std::wstring processName;
	DWORD ppid;
};

typedef struct Net_Data
{
	DWORD ProcessID;
	wstring AssemblyName;
	wstring ModuleILPath;
};

typedef struct Net_Data_Util
{
	wstring AssemblyName;
	wstring ModuleILPath;
};

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);
typedef struct _PROCESS_BASIC_INFORMATION
{
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _LISTAPROCESOSINDICE {
	wstring nombre;
	string deteccion;
	DWORD ppid;
	bool hayNET;
	bool esx86;
} LISTAPROCESOSINDICE, * PLISTAPROCESOSINDICE;

typedef struct _SECTION_IMAGE_INFORMATION
{
	PVOID EntryPoint;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR ImageFlags;
		struct
		{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR Reserved : 3;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;


typedef struct _DETECCIONES_AGRUPADAS
{
	string categoria;
	string procesos;
} DETECCIONES_AGRUPADAS;

#define FileDirectoryInformation 1   
#define STATUS_NO_MORE_FILES 0x80000006L   

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	} DUMMYUNIONNAME;
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	union {
		struct {
			WCHAR FileName[1];
		} FileDirectoryInformationClass;

		struct {
			DWORD dwUknown1;
			WCHAR FileName[1];
		} FileFullDirectoryInformationClass;

		struct {
			DWORD dwUknown2;
			USHORT AltFileNameLen;
			WCHAR AltFileName[12];
			WCHAR FileName[1];
		} FileBothDirectoryInformationClass;
	};
} FILE_QUERY_DIRECTORY, * PFILE_QUERY_DIRECTORY;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

