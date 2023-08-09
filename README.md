# WhacAMole
WhacAMole is a program that analyzes processes in memory in an integral way, detecting and alerting of anomalies related to malware and presenting and saving in files all the relevant information for verification, correlation or analysis, as well as dumping memory regions, processes and suspicious modules.
To achieve this, it analyzes not only the anomalies of the memory regions of the processes and the modules they load, but it also analyzes in depth all the memory space in use by the process.
At this moment, WhacAMole is capable of identifying 67 alerts related to malicious behavior or that can only be due to malware.
It shows more than 70 properties of the processes, memory and modules, comparing many of their attributes read in memory with those that appear in the corresponding file on disk, partially disassembles suspicious memory regions and partially disassembles exported functions that have been modified in memory for analysts to conduct their own investigations.

![Modificación de función por malware](https://github.com/ignacioj/WhacAMole/blob/main/img/modexportedfunc.png)

Unlike other similar programs, it makes all the relevant information on the processes available to analysts, labeling those characteristics that are related to malware with different alerts, so that they can carry out their own analysis or look for other signs of the existence of malicious processes.
Alerts are classified, according to their danger and the number of processes in which the same behavior appears, according to a scale of six values, reflected in the html document with a color scale, with 6 (black color) being an indicator of the probability higher than that the detected characteristic is due to malware and 1 (gray color) that, although the behavior is abnormal, there are many system processes where the same behavior has been observed:

![Color codes](https://github.com/ignacioj/WhacAMole/blob/main/img/colorcodes.jpg)

To facilitate the work of the analysts, the information is presented on screen, in an HTML file with a navigation panel of the processes analyzed and in csv text files. In the side panel of the html document, the process tree is shown, with the color corresponding to the highest alert detected in them, with the hyperlink to its location in the document, and with the blue color in its PID if it is a 32 bits process or green if it is a .NET process.

![Tree1](https://github.com/ignacioj/WhacAMole/blob/main/img/tree.jpg)

Networking capacity is displayed in two ways: if a TCP connection has been detected it is displayed with the Earth globe symbol, and if a connected socket has been detected, it is displayed with an empty globe symbol. Added symbol (white circle) for processes with http navigation libraries in memory: wininet.dll and winhttp.dll.

![TreeTCPSocket](https://github.com/ignacioj/WhacAMole/blob/main/img/treeTCPSocket.jpg)

Network detail:

![TCPDetail](https://github.com/ignacioj/WhacAMole/blob/main/img/tcpDetail.jpg)

Connected socket:

![socketDetail](https://github.com/ignacioj/WhacAMole/blob/main/img/socketDetail.jpg)

There is a special symbol (a key) when Mimikatz-like activity is detected.

![socketDetail](https://github.com/ignacioj/WhacAMole/blob/main/img/key.png)

At the bottom of the navigation panel of the html document, all the alerts are shown, with their color, with the PIDs of the processes in which they have been detected in the form of a hyperlink to the position of the document where the process is shown.

![Detections](https://github.com/ignacioj/WhacAMole/blob/main/img/detections.jpg)

If there are no processes detected with an alert, their name is displayed on a white background.

The main panel displays all processes with its information in collapsibles sections that by default are hidden. All the alerts are visible always.

![socketDetail](https://github.com/ignacioj/WhacAMole/blob/main/img/display.png)

Analyze, compare and present information from:

**1.	Processes:**
- Name of process.
- File size.
- Process PID.
- PPID of the process.
- TCP and UDP network connections.
- Informs if the process appears in four PEB lists: InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList and LdrpHashTable.
- Informs if the process is visible in the memory (VAD).
- Rich Header information.
- Exported functions read in memory and read from file.
- Imported functions.
- Delay import modules
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
- Process file path. Shows the FullName of the VAD and the PEB if they differ.
- Current working directory (CWD) of the process.
- PE format: x86/x64.
- Type of target machine (Target Machine).
- Date-time of creation of the process.
- Time elapsed from system startup to process creation.
- Signature of the PE.
- Address of the program's database file (.pdb) read in memory and in the file.
- Date-time obtained from the IMAGE_FILE_HEADER read in memory and in the file.
- Date-time obtained from the IMAGE_DEBUG_DIRECTORY read in memory and in the file.
- Date-time obtained from the IMAGE_EXPORT_DIRECTORY read in memory and in the file.
- Date-time obtained from the IMAGE_RESOURCE_DIRECTORY read in memory and in the file.
- SHA1 hash of the file.
- Information on whether it is a .NET executable and CLR version.
- Information on whether NTFS or Transactional Recording (TxF/TxR) has been detected in the process.
- Looks for suspicious environmental variables.
- Check the status of the threads.
- Gets the running tasks in the system associated with each process.

•	Warnings:
```
[Admin Privs]
[Alternate credentials]
[Alternate network credentials]
[Delphi 4 – Delphi 2006]
[Entry Point]
[LogonType]
[Managed code but no Assemblies detected - .NET ETW disabled]
[Mismatching Path]
[Name of the module hidden in memory]
[NTLM Authentication]
[PE anomalies]
[PEB ImageBaseAddress forgery]
[Possible .NET in memory loaded as Assembly.Load(byte[])]
[Process checkSum is 0]
[Process checkSum mismatch]
[Process Ghosting]
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
![Processes](https://github.com/ignacioj/WhacAMole/blob/main/img/processes.jpg)

**2.	Modules:**
- Name of the module.
- File size.
- File path. Shows the FullName of the VAD and the PEB if they differ.
- Informs if the process appears in four PEB lists: InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList and LdrpHashTable.
- Informs if the process is visible in the memory (VAD).
```
What you would expect to see in a normal module is LMIVH:
L = InLoadOrderModuleList(PEB).
M = InMemoryOrderModuleList (PEB).
I = InInitializationOrderModuleList (PEB).
V = Detected in the virtual memory of the process.
H = Detected in the PEB hash list.

If it has been unlinked from the three PEB linked lists you would see:
    ---VH

If the module is loaded manually by the malware it would not appear in any of the PEB lists but it could be detected by scanning the memory,
so It would appear as:
    −−−V−

With the DLL Hollowing with Moat technique (see https://github.com/forrest-orr/artifacts-kit for a POC) the result would be:
    -----
```
- Rich Header information.
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
[Abnormal PE Header]
[Delphi 4 – Delphi 2006]
[DLL Hiding]
[DLL Hollowing]
[Mismatching Path]
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
![Modules](https://github.com/ignacioj/WhacAMole/blob/main/img/modules.jpg)

**3.	Handles:**
All process handles of the File, Key, Mutant, Process, Thread, Token and Section types are displayed. Depending on the type of handle, the following information is displayed:
###### File: Full address of the file.
![Handle File](https://github.com/ignacioj/WhacAMole/blob/main/img/handlefile.jpg)

###### NamedPipe: Client process, server process, access granted, address of the object in the kernel.
![Named pipe](https://github.com/ignacioj/WhacAMole/blob/main/img/namedpipe.jpg)

###### Key: Full address of the key accessed.
![Handle Key](https://github.com/ignacioj/WhacAMole/blob/main/img/handlekey.jpg)

###### Mutant: Name of the mutant.
![Mutant](https://github.com/ignacioj/WhacAMole/blob/main/img/mutant.jpg)

###### Process: Process ID, process name, granted access, kernel object address.
![Handle Process](https://github.com/ignacioj/WhacAMole/blob/main/img/handleprocess.jpg)

###### Thread: Process name, process ID, thread ID, granted access, kernel object address.
![Handle Thread](https://github.com/ignacioj/WhacAMole/blob/main/img/handlethread.jpg)

###### Token: Security Identifier (SID) of the user, user and domain, Locally Unique Identifier (LUID) of the Login Session, type of token.
![Handle Token](https://github.com/ignacioj/WhacAMole/blob/main/img/handletoken.jpg)

###### Section: object name, handle ID, memory address, size, memory allocation properties, module entry point if applicable, access allowed, object address in the kernel.
![Handle Section](https://github.com/ignacioj/WhacAMole/blob/main/img/handlesection.jpg)

•	Warnings:
 ```
[Handle-Section Phantom DLL Hollowing TxF]
[Handle-Section Suspicious: Injection]
[Pipe Handle to another process]
[Process Handle to another process]
[ShadowMove Lateral Movement]
 ```
 
 **4.	Tokens:**
In threads where a token is detected, the following is displayed:
- Thread ID.
- State of the thread.
- User and domain.
- Locally Unique Identifier (LUID) of the login session.
- Locally Unique Identifier (LUID) of the login session from which it came.
- Token type.
- Token integrity.

•	Warnings:
 ```
[Thread with TOKEN]
 ```
![Tokens](https://github.com/ignacioj/WhacAMole/blob/main/img/tokens.jpg)

 **5.	Threads:**
- Thread ID.
- Thread start address.
- Full address of the module.
- State.
- Call Stack.

•	Warnings:
 ```
[Thread-Memory NOT MEM_IMAGE]
[Thread-Possible Ekko technique]
[Thread-Possible Foliage technique]
[Thread-Unknown module in Stack]
 ```
 ![Threads](https://github.com/ignacioj/WhacAMole/blob/main/img/infothreads.png)
 
 **6.	.NET assemblies**
- Application domains.
- Full address of the file.

 •	Warnings:
 ```
[.NET Assembly w/o ILPath]
 ```
 ![NET](https://github.com/ignacioj/WhacAMole/blob/main/img/net.jpg)
 
 
  **7.	Memory address space.**
Shows from all memory regions of the process the values ​​of:
- Memory address.
- Protection.
- Condition.
- Type.
- Name of the file read from the VAD.
- Size of the region.
- Base address to which your assignment belongs.
- Initial memory allocation protection.

 •	Warnings:
 ```
[Executable memory region not MEM_IMAGE]
[Hidden PE]
[Lagos Island Method]
[Mapped Image]
[Memory region hash]
[Memory region Protection value modified]
[Memory region WX]
[Memory/File values mismatch]
[Moat detected]
[MZ/PE Not Present]
[Shellcode]
[Unknown executable memory region]
 ```
 ![Memory](https://github.com/ignacioj/WhacAMole/blob/main/img/memory.jpg)
  
 ![Memory](https://github.com/ignacioj/WhacAMole/blob/main/img/memory3.jpg)
 
