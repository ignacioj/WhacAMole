#pragma once
#include <NTSecAPI.h>
#include <string>
#include <vector>
#include <sspi.h>

#define MAX_UNICODE_PATH 32767L
#define RTL_MAX_DRIVE_LETTERS 32

typedef VOID(NTAPI* _RtlInitUnicodeString) (
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);
typedef NTSTATUS(NTAPI* _RtlHashUnicodeString) (
	PUNICODE_STRING String,
	BOOLEAN          CaseInSensitive,
	ULONG            HashAlgorithm,
	PULONG           HashValue
	);

typedef struct _SECTION_BASIC_INFORMATION
{
	PVOID BaseAddress;
	ULONG AllocationAttributes;
	LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION, * PSECTION_BASIC_INFORMATION;
typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
	SectionRelocationInformation, 
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;


typedef struct _PEB_LDR_DATA {					//x64	x32
	ULONG Length;							
	BOOLEAN Initialized;						//0x04	0x04
	PVOID SsHandle;								//0x08	0x08
	LIST_ENTRY InLoadOrderModuleList;			//0x10	0x0c
	LIST_ENTRY InMemoryOrderModuleList;			//0x20	0x14
	LIST_ENTRY InInitializationOrderModuleList;	//0x30	0x1c
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;
typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x4
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x8
			UCHAR Balance : 2;                                                //0x8
		};
		ULONG ParentValue;                                                  //0x8
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;
typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;
typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;
typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union
	{
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;
typedef struct _LDR_DATA_TABLE_ENTRY
{													//x64		x32
	LIST_ENTRY InLoadOrderLinks;					//0x00		0x00
	LIST_ENTRY InMemoryOrderLinks;					//0x10		0x08
	union											//0x20		0x10
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;									//0x30		0x18
	PVOID EntryPoint;								//0x38		0x1c
	ULONG SizeOfImage;								//0x40		0x20
	UNICODE_STRING FullDllName;						//0x48 		0x24
	UNICODE_STRING BaseDllName;						//0x58 		0x2c
	union											//0x68		0x34
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;						//0x6c		0x38
	USHORT TlsIndex;								//0x6e		0x3a
	LIST_ENTRY HashLinks;							//0x70		0x3c
	ULONG TimeDateStamp;							//0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;//0x88		0x48
	PVOID Lock; // RtlAcquireSRWLockExclusive		//0x90		0x4c
	PLDR_DDAG_NODE DdagNode;						//0x98
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;							//0x0f8		0x80
	LARGE_INTEGER LoadTime;							//0x100		0x88
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;  //+0x38
	UNICODE_STRING          CommandLine;    //+0x70
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct tagRTL_BITMAP {
	ULONG  SizeOfBitMap; /* Number of bits in the bitmap */
	PULONG Buffer; /* Bitmap data, assumed sized to a DWORD boundary */
} RTL_BITMAP, * PRTL_BITMAP;

typedef struct _PEB
	{                                                                 /* win32/win64 */
		BOOLEAN                      InheritedAddressSpace;             /* 000/000 */
		BOOLEAN                      ReadImageFileExecOptions;          /* 001/001 */
		BOOLEAN                      BeingDebugged;                     /* 002/002 */
		BOOLEAN                      SpareBool;                         /* 003/003 */
		HANDLE                       Mutant;                            /* 004/008 */
		HMODULE                      ImageBaseAddress;                  /* 008/010 */
		PPEB_LDR_DATA                LdrData;                           /* 00c/018 */
		RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 /* 010/020 */
		PVOID                        SubSystemData;                     /* 014/028 */
		HANDLE                       ProcessHeap;                       /* 018/030 */
		PRTL_CRITICAL_SECTION        FastPebLock;                       /* 01c/038 */
		PVOID /*PPEBLOCKROUTINE*/    FastPebLockRoutine;                /* 020/040 */
		PVOID /*PPEBLOCKROUTINE*/    FastPebUnlockRoutine;              /* 024/048 */
		ULONG                        EnvironmentUpdateCount;            /* 028/050 */
		PVOID                        KernelCallbackTable;               /* 02c/058 */
		ULONG                        Reserved[2];                       /* 030/060 */
		PVOID /*PPEB_FREE_BLOCK*/    FreeList;                          /* 038/068 */
		ULONG                        TlsExpansionCounter;               /* 03c/070 */
		PRTL_BITMAP                  TlsBitmap;                         /* 040/078 */
		ULONG                        TlsBitmapBits[2];                  /* 044/080 */
		PVOID                        ReadOnlySharedMemoryBase;          /* 04c/088 */
		PVOID                        ReadOnlySharedMemoryHeap;          /* 050/090 */
		PVOID*						 ReadOnlyStaticServerData;          /* 054/098 */
		PVOID                        AnsiCodePageData;                  /* 058/0a0 */
		PVOID                        OemCodePageData;                   /* 05c/0a8 */
		PVOID                        UnicodeCaseTableData;              /* 060/0b0 */
		ULONG                        NumberOfProcessors;                /* 064/0b8 */
		ULONG                        NtGlobalFlag;                      /* 068/0bc */
		LARGE_INTEGER                CriticalSectionTimeout;            /* 070/0c0 */
		SIZE_T                       HeapSegmentReserve;                /* 078/0c8 */
		SIZE_T                       HeapSegmentCommit;                 /* 07c/0d0 */
		SIZE_T                       HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
		SIZE_T                       HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
		ULONG                        NumberOfHeaps;                     /* 088/0e8 */
		ULONG                        MaximumNumberOfHeaps;              /* 08c/0ec */
		PVOID* ProcessHeaps;                      /* 090/0f0 */
		PVOID                        GdiSharedHandleTable;              /* 094/0f8 */
		PVOID                        ProcessStarterHelper;              /* 098/100 */
		PVOID                        GdiDCAttributeList;                /* 09c/108 */
		PVOID                        LoaderLock;                        /* 0a0/110 */
		ULONG                        OSMajorVersion;                    /* 0a4/118 */
		ULONG                        OSMinorVersion;                    /* 0a8/11c */
		ULONG                        OSBuildNumber;                     /* 0ac/120 */
		ULONG                        OSPlatformId;                      /* 0b0/124 */
		ULONG                        ImageSubSystem;                    /* 0b4/128 */
		ULONG                        ImageSubSystemMajorVersion;        /* 0b8/12c */
		ULONG                        ImageSubSystemMinorVersion;        /* 0bc/130 */
		ULONG                        ImageProcessAffinityMask;          /* 0c0/134 */
		HANDLE                       GdiHandleBuffer[28];               /* 0c4/138 */
		ULONG                        unknown[6];                        /* 134/218 */
		PVOID                        PostProcessInitRoutine;            /* 14c/230 */
		PRTL_BITMAP                  TlsExpansionBitmap;                /* 150/238 */
		ULONG                        TlsExpansionBitmapBits[32];        /* 154/240 */
		ULONG                        SessionId;                         /* 1d4/2c0 */
		ULARGE_INTEGER               AppCompatFlags;                    /* 1d8/2c8 */
		ULARGE_INTEGER               AppCompatFlagsUser;                /* 1e0/2d0 */
		PVOID                        ShimData;                          /* 1e8/2d8 */
		PVOID                        AppCompatInfo;                     /* 1ec/2e0 */
		UNICODE_STRING               CSDVersion;                        /* 1f0/2e8 */
		PVOID                        ActivationContextData;             /* 1f8/2f8 */
		PVOID                        ProcessAssemblyStorageMap;         /* 1fc/300 */
		PVOID                        SystemDefaultActivationData;       /* 200/308 */
		PVOID                        SystemAssemblyStorageMap;          /* 204/310 */
		SIZE_T                       MinimumStackCommit;                /* 208/318 */
		PVOID* FlsCallback;                       /* 20c/320 */
		LIST_ENTRY                   FlsListHead;                       /* 210/328 */
		PRTL_BITMAP                  FlsBitmap;                         /* 218/338 */
		ULONG                        FlsBitmapBits[4];                  /* 21c/340 */
} PEB, * PPEB;

typedef struct _PEB64
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;                                 //0x000
			BYTE ReadImageFileExecOptions;                              //0x001
			BYTE BeingDebugged;                                         //0x002
			BYTE _SYSTEM_DEPENDENT_01;                                  //0x003
		} flags;
		uint64_t dummyalign;
	} dword0;
	uint64_t                           Mutant;                             //0x0008
	uint64_t                           ImageBaseAddress;                   //0x0010
	int* __ptr64                           Ldr;                                //0x0018
	int* __ptr64                           ProcessParameters;                  //0x0020 / pointer to RTL_USER_PROCESS_PARAMETERS64
	uint64_t                           SubSystemData;                      //0x0028
	uint64_t                           ProcessHeap;                        //0x0030
	uint64_t                           FastPebLock;                        //0x0038
	uint64_t                           _SYSTEM_DEPENDENT_02;               //0x0040
	uint64_t                           _SYSTEM_DEPENDENT_03;               //0x0048
	uint64_t                           _SYSTEM_DEPENDENT_04;               //0x0050
	union
	{
		uint64_t                       KernelCallbackTable;                //0x0058
		uint64_t                       UserSharedInfoPtr;                  //0x0058
	};
	DWORD                           SystemReserved;                     //0x0060
	DWORD                           _SYSTEM_DEPENDENT_05;               //0x0064
	uint64_t                           _SYSTEM_DEPENDENT_06;               //0x0068
	uint64_t                           TlsExpansionCounter;                //0x0070
	uint64_t                           TlsBitmap;                          //0x0078
	DWORD                           TlsBitmapBits[2];                   //0x0080
	uint64_t                           ReadOnlySharedMemoryBase;           //0x0088
	uint64_t                           _SYSTEM_DEPENDENT_07;               //0x0090
	uint64_t                           ReadOnlyStaticServerData;           //0x0098
	uint64_t                           AnsiCodePageData;                   //0x00A0
	uint64_t                           OemCodePageData;                    //0x00A8
	uint64_t                           UnicodeCaseTableData;               //0x00B0
	DWORD                           NumberOfProcessors;                 //0x00B8
	union
	{
		DWORD                       NtGlobalFlag;                       //0x00BC
		DWORD                       dummy02;                            //0x00BC
	};
	LARGE_INTEGER                   CriticalSectionTimeout;             //0x00C0
	uint64_t                           HeapSegmentReserve;                 //0x00C8
	uint64_t                           HeapSegmentCommit;                  //0x00D0
	uint64_t                           HeapDeCommitTotalFreeThreshold;     //0x00D8
	uint64_t                           HeapDeCommitFreeBlockThreshold;     //0x00E0
	DWORD                           NumberOfHeaps;                      //0x00E8
	DWORD                           MaximumNumberOfHeaps;               //0x00EC
	uint64_t                           ProcessHeaps;                       //0x00F0
	uint64_t                           GdiSharedHandleTable;               //0x00F8
	uint64_t                           ProcessStarterHelper;               //0x0100
	uint64_t                           GdiDCAttributeList;                 //0x0108
	uint64_t                           LoaderLock;                         //0x0110
	DWORD                           OSMajorVersion;                     //0x0118
	DWORD                           OSMinorVersion;                     //0x011C
	WORD                            OSBuildNumber;                      //0x0120
	WORD                            OSCSDVersion;                       //0x0122
	DWORD                           OSPlatformId;                       //0x0124
	DWORD                           ImageSubsystem;                     //0x0128
	DWORD                           ImageSubsystemMajorVersion;         //0x012C
	uint64_t                           ImageSubsystemMinorVersion;         //0x0130
	union
	{
		uint64_t                       ImageProcessAffinityMask;           //0x0138
		uint64_t                       ActiveProcessAffinityMask;          //0x0138
	};
	uint64_t                           GdiHandleBuffer[30];                //0x0140
	uint64_t                           PostProcessInitRoutine;             //0x0230
	uint64_t                           TlsExpansionBitmap;                 //0x0238
	DWORD                           TlsExpansionBitmapBits[32];         //0x0240
	uint64_t                           SessionId;                          //0x02C0
	ULARGE_INTEGER                  AppCompatFlags;                     //0x02C8
	ULARGE_INTEGER                  AppCompatFlagsUser;                 //0x02D0
	uint64_t                           pShimData;                          //0x02D8
	uint64_t                           AppCompatInfo;                      //0x02E0
} PEB64, * PPEB64;

typedef struct _PEB32
{
	BOOLEAN                         InheritedAddressSpace;              //0x0000
	BOOLEAN                         ReadImageFileExecOptions;           //0x0001
	BOOLEAN                         BeingDebugged;                      //0x0002
	union
	{
		BOOLEAN                     SpareBool;                          //0x0003 (NT3.51-late WS03)
		struct
		{
			BYTE                    ImageUsesLargePages : 1;   //0x0003:0 (WS03_SP1+)
			BYTE                    IsProtectedProcess : 1;   //0x0003:1 (Vista+)
			BYTE                    IsLegacyProcess : 1;   //0x0003:2 (Vista+)
			BYTE                    IsImageDynamicallyRelocated : 1;   //0x0003:3 (Vista+)
			BYTE                    SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
			BYTE                    IsPackagedProcess : 1;   //0x0003:5 (Win8_BETA+)
			BYTE                    IsAppContainer : 1;   //0x0003:6 (Win8_RTM+)
			BYTE                    SpareBit : 1;   //0x0003:7
		} bits;
	} byte3;
	uint32_t                          Mutant;                             //0x0004
	uint32_t ImageBaseAddress;                   //0x0008
	uint32_t Ldr;                                //0x000C  (all loaded modules in process)
	uint32_t ProcessParameters;                  //0x0010
	uint32_t SubSystemData;                      //0x0014
	uint32_t ProcessHeap;                        //0x0018
	uint32_t FastPebLock;                        //0x001C
	union
	{
		uint32_t FastPebLockRoutine;                 //0x0020 (NT3.51-Win2k)
		uint32_t SparePtr1;                          //0x0020 (early WS03)
		uint32_t AtlThunkSListPtr;                   //0x0020 (late WS03+)
	} dword20;
	union
	{
		uint32_t FastPebUnlockRoutine;               //0x0024 (NT3.51-XP)
		uint32_t SparePtr2;                          //0x0024 (WS03)
		uint32_t IFEOKey;                            //0x0024 (Vista+)
	} dword24;
	union
	{
		uint32_t                       EnvironmentUpdateCount;             //0x0028 (NT3.51-WS03)
		struct
		{
			uint32_t                   ProcessInJob : 1;        //0x0028:0 (Vista+)
			uint32_t                   ProcessInitializing : 1;        //0x0028:1 (Vista+)
			uint32_t                   ProcessUsingVEH : 1;        //0x0028:2 (Vista_SP1+)
			uint32_t                   ProcessUsingVCH : 1;        //0x0028:3 (Vista_SP1+)
			uint32_t                   ProcessUsingFTH : 1;        //0x0028:4 (Win7_BETA+)
			uint32_t                   ReservedBits0 : 27;       //0x0028:5 (Win7_BETA+)
		} vista_CrossProcessFlags;
	} struct28;
	union
	{
		uint32_t KernelCallbackTable;                //0x002C (Vista+)
		uint32_t UserSharedInfoPtr;                  //0x002C (Vista+)
	} dword2C;
	uint32_t                           SystemReserved;                     //0x0030 (NT3.51-XP)
	//Microsoft seems to keep changing their mind with DWORD 0x34
	union
	{
		uint32_t                       SystemReserved2;                    //0x0034 (NT3.51-Win2k)
		struct
		{
			uint32_t                   ExecuteOptions : 2;        //0x0034:0 (XP-early WS03) 
			uint32_t                   SpareBits : 30;       //0x0034:2 (XP-early WS03)
		} xpBits;
		uint32_t                       AtlThunkSListPtr32;                 //0x0034 (late XP,Win7+)
		uint32_t                       SpareUlong;                         //0x0034 (late WS03-Vista)
		struct
		{
			uint32_t                   HeapTracingEnabled : 1;        //0x0034:0 (Win7_BETA)
			uint32_t                   CritSecTracingEnabled : 1;        //0x0034:1 (Win7_BETA)
			uint32_t                   SpareTracingBits : 30;       //0x0034:2 (Win7_BETA)
		} win7_TracingFlags;
	} dword34;
	union
	{
		uint32_t FreeList;                           //0x0038 (NT3.51-early Vista)
		uint32_t                       SparePebPtr0;                       //0x0038 (last Vista)
		uint32_t ApiSetMap;                          //0x0038 (Win7+)
	} dword38;
	uint32_t                           TlsExpansionCounter;                //0x003C
	uint32_t TlsBitmap;                          //0x0040
	uint32_t                           TlsBitmapBits[2];                   //0x0044
	uint32_t ReadOnlySharedMemoryBase;           //0x004C
	union
	{
		uint32_t ReadOnlyShareMemoryHeap;            //0x0050 (NT3.51-WS03)
		uint32_t HotpatchInformation;                //0x0050 (Vista+)
	} dword50;
	uint32_t ReadOnlyStaticServerData;           //0x0054
	uint32_t AnsiCodePageData;                   //0x0058
	uint32_t OemCodePageData;                    //0x005C
	uint32_t UnicodeCaseTableData;               //0x0060
	uint32_t                           NumberOfProcessors;                 //0x0064
	uint32_t                           NtGlobalFlag;                       //0x0068
	LARGE_INTEGER                   CriticalSectionTimeout;             //0x0070
	uint32_t                           HeapSegmentReserve;                 //0x0078
	uint32_t                           HeapSegmentCommit;                  //0x007C
	uint32_t                           HeapDeCommitTotalFreeThreshold;     //0x0080
	uint32_t                           HeapDeCommitFreeBlockThreshold;     //0x0084
	uint32_t                           NumberOfHeaps;                      //0x0088
	uint32_t                           MaximumNumberOfHeaps;               //0x008C
	uint32_t ProcessHeaps;                       //0x0090
	uint32_t GdiSharedHandleTable;               //0x0094
} PEB32, * PPEB32;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation
} PROCESSINFOCLASS;

typedef struct _REGIONES_EJECUTABLES {
	uint64_t regionAddress{};
	string proteccion{};
	string proteccionPrevia{};
	bool alerta{};
	bool MEM_WX{};
	bool regDesconocida{};
	bool privateMemory{};
	bool modifProtection{};
	bool hashMismatch{};
	string SHA1hash{};
	string SHA1hashFF{};
	string nombreSecc{};
} REGIONES_EJECUTABLES;

typedef struct _INFO_SECCIONES {
	string Name;
	DWORD   PhysicalAddress;
	DWORD   VirtualSize;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   Characteristics;
} INFO_SECCIONES;

typedef struct _MEMMODULE_ENTRY_FF {
	wstring FullName;
	WORD    nSectionCount;
	DWORD   EntryPointFile;
	DWORD       CheckSumOriginal;
	//
	DWORD CheckSumComputed;
	wstring PE32;
	bool NetImage; 
	DWORD lfanew;
	DWORD fileSize;
	bool DelphiAlerta;
	vector<string> DebugDirectoryTimeDateStampFF;
	string DebugDirectoryPDBFF;
	string FileHeaderTimeDateStampFF;
	string ExportDirectoryTimeDateStampFF;
	string ResourceDirectoryTimeDateStampFF;
	string vCLRFF;
	DWORD numExportsFF;
	string nombresSeccionesFF;
	map<DWORD, INFO_SECCIONES> SeccionesPEFF;
	wstring productName;
	wstring fileDesc;
	wstring companyName;
	wstring internalName;
	wstring originalFileName;
	wstring comments;
	wstring fileVersion;
	wstring legalCopyright;
	wstring legalTrademarks;
	wstring productVersion;
	wstring privateBuild;
	wstring specialBuild;
	WORD    Machine;
	DWORD   SizeOfImage;
	DWORD   SizeOfInitializedData;
	WORD    DllCharacteristics;
	WORD    MajorImageVersion;
} MEMMODULE_ENTRY_FF, * PMEMMODULE_ENTRY_FF;

typedef struct _MEMMODULE_ENTRY {
	bool esDLL;		
	wchar_t BaseName[MAX_PATH]; 
	wstring modName; 
	wstring VADFullName; 
	wstring PEBFullName;
	DWORD EntryPointMem; 
	bool sinSeccionesMemoria; 
	LARGE_INTEGER LoadTime;
	WCHAR infoListas[6]; 
	bool NetImage; 
	uint64_t VADBaseAddress;
	uint64_t ldrBaseAddress;
	uint64_t AllocationBase;
	DWORD AllocationProtect;
	wstring wsAllocationProtect;
	uint64_t RegionSize;
	uint64_t ReservationSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;  
	wstring wsType;
	bool malformedPE;
	int offsetTextMemNoEmpty;
	wstring PE32;
	DWORD SizeOfInitializedData;
	WORD DLLCharacteristics;
	WORD MajorImageVersion;
	DWORD SizeOfImage;
	DWORD CheckSumMem;
	bool PEnotMEMIMAGE;
	wstring Signature;
	DWORD SectionAlignment;
	vector<string> DebugDirectoryTimeDateStamp;
	string DebugDirectoryPDB;
	string FileHeaderTimeDateStamp;
	string ExportDirectoryTimeDateStamp;
	string ResourceDirectoryTimeDateStamp;
	string vCLR;
	DWORD numExports;
	bool possNET;
	DWORD possNETOffset;
	bool exeMem;
	int exeMemOffset;
	bool shellcode;
	DWORD shellcodeOffset;
	DWORD lfanew;
	string nombresSecciones;
	bool seccionesModificadas;
	map<DWORD, INFO_SECCIONES> SeccionesPE;
	map<DWORD, REGIONES_EJECUTABLES> RegionesXMemoria;
	bool buscaHooks;
	WORD machine;
	uint64_t offsetResDirectory;
	wstring productNameFM;
	wstring fileDescFM;
	wstring companyNameFM;
	wstring internalNameFM;
	wstring originalFileNameFM;
	wstring commentsFM;
	wstring fileVersionFM;
	wstring legalCopyrightFM;
	wstring legalTrademarksFM;
	wstring productVersionFM;
	wstring privateBuildFM;
	wstring specialBuildFM;
	DWORD fosoPE;
	vector<string> importModules;
	vector<string> delayImportModules;
	bool hiddenPE;
	bool DelphiAlerta;
	vector<string> richHeader;
} MEMMODULE_ENTRY, * PMEMMODULE_ENTRY;

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);

typedef struct _UNICODE_STRING32 {
	USHORT Length;
	USHORT MaximumLength;
	DWORD Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;


#define WOW64_POINTER(Type) ULONG

typedef struct _RTL_BALANCED_NODE32
{
	union
	{
		WOW64_POINTER(struct _RTL_BALANCED_NODE*) Children[2];
		struct
		{
			WOW64_POINTER(struct _RTL_BALANCED_NODE*) Left;
			WOW64_POINTER(struct _RTL_BALANCED_NODE*) Right;
		};
	};
	union
	{
		WOW64_POINTER(UCHAR) Red : 1;
		WOW64_POINTER(UCHAR) Balance : 2;
		WOW64_POINTER(ULONG_PTR) ParentValue;
	};
} RTL_BALANCED_NODE32, * PRTL_BALANCED_NODE32;

typedef enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonEnclavePrimary, 
	LoadReasonEnclaveDependency,
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	union
	{
		LIST_ENTRY32 InInitializationOrderLinks;
		LIST_ENTRY32 InProgressLinks;
	};
	WOW64_POINTER(PVOID) DllBase;
	WOW64_POINTER(PVOID) EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
	WOW64_POINTER(struct _ACTIVATION_CONTEXT*) EntryPointActivationContext;
	WOW64_POINTER(PVOID) Lock;
	WOW64_POINTER(PLDR_DDAG_NODE) DdagNode;
	LIST_ENTRY32 NodeModuleLink;
	WOW64_POINTER(struct _LDRP_LOAD_CONTEXT*) LoadContext;
	WOW64_POINTER(PVOID) ParentDllBase;
	WOW64_POINTER(PVOID) SwitchBackContext;
	RTL_BALANCED_NODE32 BaseAddressIndexNode;
	RTL_BALANCED_NODE32 MappingInfoIndexNode;
	WOW64_POINTER(ULONG_PTR) OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel; 
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

char* KTHREAD_STATE[]
{
	"Initialized",
	"Ready",
	"Running",
	"Standby",
	"Terminated",
	"Waiting",
	"Transition",
	"DeferredReady",
	"GateWaitObsolete",
	"WaitingForProcessInSwap",
	"MaximumThreadState"
};

char* KWAIT_REASON[]
{
	"Executive",
	"FreePage",
	"PageIn",
	"PoolAllocation",
	"DelayExecution",
	"Suspended",
	"UserRequest",
	"WrExecutive",
	"WrFreePage",
	"WrPageIn",
	"WrPoolAllocation",
	"WrDelayExecution",
	"WrSuspended",
	"WrUserRequest",
	"WrEventPair",
	"WrQueue",
	"WrLpcReceive",
	"WrLpcReply",
	"WrVirtualMemory",
	"WrPageOut",
	"WrRendezvous",
	"WrKeyedEvent",
	"WrTerminated",
	"WrProcessInSwap",
	"WrCpuRateControl",
	"WrCalloutStack",
	"WrKernel",
	"WrResource",
	"WrPushLock",
	"WrMutex",
	"WrQuantumEnd",
	"WrDispatchInt",
	"WrPreempted",
	"WrYieldExecution",
	"WrFastMutex",
	"WrGuardedMutex",
	"WrRundown",
	"WrAlertByThreadId",
	"WrDeferredPreempt",
	"MaximumWaitReason"
};

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; 
	ULONG HardFaultCount; 
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	LPVOID UniqueProcessId;
	LPVOID InheritedFromUniqueProcessId;	
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; 
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1]; 
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

