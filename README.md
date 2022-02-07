## WhacAMole
WhacAMole is a program that analyzes processes in memory in an integral way, detecting and alerting of anomalies related to malware and presenting and saving in files all the relevant information for verification, correlation or analysis, as well as dumping memory regions, processes and suspicious modules.
To achieve this, it analyzes not only the anomalies of the memory regions of the processes and the modules they load, but it also analyzes in depth all the memory space in use by the process.
At this moment, WhacAMole is capable of identifying 67 alerts related to malicious behavior or that can only be due to malware.
It shows more than 70 properties of the processes, memory and modules, comparing many of their attributes read in memory with those that appear in the corresponding file on disk, partially disassembles suspicious memory regions and partially disassembles exported functions that have been modified in memory for analysts to conduct their own investigations.

![Modificación de función por malware](https://github.com/ignacioj/WhacAMole/blob/main/res/modexportedfunc.png)

Unlike other similar programs, it makes all the relevant information on the processes available to analysts, labeling those characteristics that are related to malware with different alerts, so that they can carry out their own analysis or look for other signs of the existence of malicious processes.
Alerts are classified, according to their danger and the number of processes in which the same behavior appears, according to a scale of six values, reflected in the html document with a color scale, with 6 (black color) being an indicator of the probability higher than that the detected characteristic is due to malware and 1 (gray color) that, although the behavior is abnormal, there are many system processes where the same behavior has been observed:

![Color codes](https://github.com/ignacioj/WhacAMole/blob/main/res/colorcodes.jpg)

To facilitate the work of the analysts, the information is presented on screen, in an HTML file with a navigation panel of the processes analyzed and in csv text files. In the side panel of the html document, the process tree is shown, with the color corresponding to the highest alert detected in them, with the hyperlink to its location in the document, and with the blue color in its PID if it is a 32 bits process or green if it is a .NET process.

![Tree1](https://github.com/ignacioj/WhacAMole/blob/main/res/tree.jpg)

At the bottom of the navigation panel of the html document, all the alerts are shown, with their color, with the PIDs of the processes in which they have been detected in the form of a hyperlink to the position of the document where the process is shown.

![Detections](https://github.com/ignacioj/WhacAMole/blob/main/res/detections.jpg)

If there are no processes detected with an alert, their name is displayed on a white background.

Analyze, compare and present information from:

**1.	Processes:**
- Name of process.
- File size.
- Process PID.
- PPID of the process.
- TCP and UDP network connections.
- Informs if the process appears in four PEB lists: InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList and LdrpHashTable.
- Informs if the process is visible in the memory (VAD).
- Exported functions read in memory and read from file.
- Imported functions.
- Protection of the memory assigned to the process module.
- Memory type.
- Process entry point read into memory.
- Entry point of the process read from your file.
- Memory address of the process.
- PE sections read in memory and in the file. Both are only displayed if there is a difference.
- PE data section size.
- Characteristics of the executable (DLLCharacteristics).
- The major version number of the image (MajorImageVersion).
- Original and calculated checksum.
- From the VERSIONINFO resource, read from memory and from the file, it shows the values of: Comments, CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, LegalTrademarks, OriginalFilename, PrivateBuild, ProductName, ProductVersion, SpecialBuild.
- Session ID of the process obtained from the Local Security Authority (LSA).
- Session ID visible from the process.
- Login Session Locally Unique Identifier (LUID).
- Locally Unique Identifier (LUID) of the login Session of the process from which it originates.
- Token integrity.
- Token type.
- Type of logon.
- Authentication package used.
- User and domain.
- Security identifier (SID) of the user.
- Membership in the local administrators group.
- Process command line.
- Process file path.
- Current working directory (CWD) of the process.
- PE format: x86/x64.
- Type of target machine (Target Machine).
- Date-time of creation of the process.
- Time elapsed from system startup to process creation.
- Signature of the EP.
- Address of the program's database file (.pdb) read in memory and in the file.
- Date-time obtained from the IMAGE_FILE_HEADER read in memory and in the file.
- Date-time obtained from the IMAGE_DEBUG_DIRECTORY read in memory and in the file.
- Date-time obtained from the IMAGE_EXPORT_DIRECTORY read in memory and in the file.
- Date-time obtained from the IMAGE_RESOURCE_DIRECTORY read in memory and in the file.
- SHA1 hash of the file.
- Information on whether it is a .NET executable and CLR version.
- Information on whether NTFS or Transactional Recording (TxF/TxR) has been detected in the process.

•	Warnings:
```
[Admin Privs]
[Alternate credentials]
[Alternate network credentials]
[Delphi 4 – Delphi 2006]
[Entry Point]
[LogonType]
[Managed code but no Assemblies detected - .NET ETW disabled]
[Name of the module hidden in memory]
[NTLM Authentication]
[PE anomalies]
[PEB ImageBaseAddress forgery]
[Possible .NET in memory loaded as Assembly.Load(byte[])]
[Process checkSum is 0]
[Process checkSum mismatch]
[Process Hollowing]
[Process Memory region hash mismatch]
[Process Memory region Protection value modified]
[Process Memory region WX]
[Process Name != Internal Name]
[PROCESS NOT SIGNED]
[Process Private memory region]
[Process Unknown executable memory region]
[Section Table]
[Shared memory subversion]
[SizeOfInitializedData is 0]
[SUSPENDED PROCESS]
[Suspicious Commandline]
[Suspicious Environment Variable]
[TimeDateStamp Inequality]
[Transaction detected: TxF/TxR]
[Unmanaged process/managed code execution detected]
[Unusual CWD]
```
![Processes](https://github.com/ignacioj/WhacAMole/blob/main/res/processes.jpg)

**2.	Modules:**
- Name of the module.
- File size.
- Informs if the process appears in four PEB lists: InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList and LdrpHashTable.
- Informs if the process is visible in the memory (VAD).
- Exported functions read in memory and read from file.
- Protection of the memory assigned to the module.
- Memory type.
- Process entry point read into memory.
- Entry point of the process read from your file.
- Memory address of the process.
- PE sections read in memory and in the file. Both are only displayed if there is a difference.
- PE data section size.
- Characteristics of the executable (DLLCharacteristics).
- The major version number of the image (MajorImageVersion).
- Original and calculated checksum.
- PE format: x86/x64.
- Type of target machine (Target Machine).
- Date-time of loading of the module in memory.
- From the VERSIONINFO resource, read from memory and from the file, it shows the values of: Comments, CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, LegalTrademarks, OriginalFilename, PrivateBuild, ProductName, ProductVersion, SpecialBuild.
- Signature of the EP.
- Address of the program's database file (.pdb) read in memory and in the file.
- Date-time obtained from the IMAGE_FILE_HEADER read in memory and in the file.
- Date-time obtained from the IMAGE_DEBUG_DIRECTORY read in memory and in the file.
- Date-time obtained from the IMAGE_EXPORT_DIRECTORY read in memory and in the file.
- Date-time obtained from the IMAGE_RESOURCE_DIRECTORY read in memory and in the file.
- SHA1 hash of the file.
- Information on whether it is a .NET executable and CLR version.

•	Warnings:
```
[Delphi 4 – Delphi 2006]
[DLL Hollowing]
[Module checkSum is 0]
[Module checkSum mismatch]
[Module Name != OriginalFileName]
[MODULE NOT SIGNED]
[Module PE anomalies]
[Module SizeOfInitializedData is 0]
[Module TimeDateStamp Inequality]
[Name of the module hidden in memory]
[Phantom DLL Hollowing TxF]
[Private memory region]
[Section Table]
[Signed PE NOT MEM_IMAGE]
[Unsigned PE NOT MEM_IMAGE]
[Unusual module]
 ```
![Modules](https://github.com/ignacioj/WhacAMole/blob/main/res/modules.jpg)



