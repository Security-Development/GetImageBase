#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);

typedef struct _PEB
{
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;


typedef NTSTATUS(WINAPI *funcNtQueryInformationProcess)(
		HANDLE ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength	
	);
	
BOOL TokenEscalation(LPCTSTR privelege) {
	
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	
	if( OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE)
		if( LookupPrivilegeValue(NULL, privelege, &luid) != FALSE ) {
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			
			if( AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) != FALSE) 
				printf("[+] Privilege elevation completed successfully\n");
			
		}
	
	CloseHandle(hToken);
	
}


PVOID dwGetBaseAddress(HANDLE hProcess)
{
	HMODULE hModule = LoadLibraryA("ntdll.dll");
	PROCESS_BASIC_INFORMATION pbi = {};
	memset(&pbi, 0, sizeof(pbi));
	DWORD dwLength = 0;
	FARPROC fNtQueryInformationProcess = GetProcAddress(hModule, "NtQueryInformationProcess");
	funcNtQueryInformationProcess NtQueryInformationProcess =  (funcNtQueryInformationProcess)fNtQueryInformationProcess;
	
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength );
	
	return (PVOID)pbi.PebBaseAddress;
}

HANDLE GetProcessHandle(DWORD pid) {
	PROCESSENTRY32 pe32;
	
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ret = NULL, snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	
	if( !Process32First(snap, &pe32) )
		return 0;
	
	do{
		if( pe32.th32ParentProcessID = pid ) {
			ret = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			break;
		} 
	} while( Process32Next(snap, &pe32) );	
	
	return ret;
}

int main() {
	TokenEscalation(SE_DEBUG_NAME);
	
	DWORD pid;
	printf("[*] PID : ");
	scanf("%ld", &pid);
	
	HANDLE hProcess = GetProcessHandle(pid);
	PPEB peb = (PPEB)dwGetBaseAddress(hProcess);
	PEB peb32;
	
	ReadProcessMemory(hProcess, (void*)peb, &peb32, sizeof(PEB), NULL);
	
	PVOID ImageBase = peb32.Reserved3[1]; //[1] is ImageBase Address
	PBYTE pe[0x40]; // DOS HEADER SIZE is 64byte
	PBYTE nt[0x8f]; // NT HEADER SIZE is 153byte
	PBYTE iat[0x200]; // IMAGE_IMPORT_DESCRIPTOR SIZE is 20byte
	PBYTE thunk[0x50];
	PBYTE section[0x200];
	
	ReadProcessMemory(hProcess, ImageBase, pe, 0x40, NULL);
	
	PIMAGE_DOS_HEADER HEADER = (PIMAGE_DOS_HEADER)pe;
	
	ReadProcessMemory(hProcess, ImageBase + HEADER->e_lfanew, nt, 0x8f, NULL);
	
	PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS)nt;
	
	ReadProcessMemory(hProcess, ImageBase + NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, iat, 0, NULL);
	
	PIMAGE_IMPORT_DESCRIPTOR IDD = (PIMAGE_IMPORT_DESCRIPTOR) iat;
	
	ReadProcessMemory(hProcess, (LPCVOID)ImageBase + NT->FileHeader.SizeOfOptionalHeader + sizeof(NT->FileHeader) + 0x4 + HEADER->e_lfanew, section, 0x200, NULL);
	
	PIMAGE_SECTION_HEADER SECTION = (PIMAGE_SECTION_HEADER)section;
	
	printf("= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =\n");
	printf("[*] Target PID : %d\n", pid);
	printf("[+] PEB : 0x%x\n", peb);
	printf("[+] ImageBase : 0x%x\n", ImageBase); 
	printf("= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =\n");
	printf("[+] DOS Offset : 0x0 ~ 0x39\n");
	printf("[+] DOS Stub Offset : 0x40 ~ 0x%x\n", HEADER->e_lfanew - 0x1);
	printf("[+] NT Offset : 0x%x ~ 0x%x\n", HEADER->e_lfanew, (HEADER->e_lfanew + 0x8f) - 0x1);
	printf("[+] SECTION Offset : 0x%x ~ 0x%x\n", HEADER->e_lfanew + 0x8f, ((HEADER->e_lfanew + 0x8f - 0x1) + (0x28 * NT->FileHeader.NumberOfSections))) ; //Section Header struct Size 40byte
	printf("= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =\n");
	printf("[+] DOS : 0x%x == %s\n", HEADER->e_magic, &HEADER->e_magic);
	printf("[+] NT : 0x%x == %s\n", NT->Signature, &NT->Signature);
	printf("= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =\n");
	printf("[+] SECTION VirtualAddress : 0x%x\n", SECTION->VirtualAddress);
	printf("[+] SECTION PointerToRawData : 0x%x\n", SECTION->PointerToRawData);
	printf("= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =\n");
	
	ReadProcessMemory(hProcess, (LPVOID)NT->OptionalHeader.ImageBase + IDD->OriginalFirstThunk, thunk, 0x50, NULL);
	PIMAGE_THUNK_DATA THUNK = (PIMAGE_THUNK_DATA)thunk;
	
	/**
		Proceeding
	**/
	
	
	for(int i = 0;  IDD[i].FirstThunk ; i++) {
		PBYTE dllName[0x100];
		
		ReadProcessMemory(hProcess, ImageBase + IDD[i].Name, dllName, 0x100, NULL);
		
		printf("%s\n", dllName);
	}	
	printf("[+] Library Name Address RVA : 0x%x\n", SECTION->PointerToRawData);
	return 0;
}
