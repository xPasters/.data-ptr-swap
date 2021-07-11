#pragma once
#include "imports.h"
#define MM_UNLOADED_DRIVERS_SIZE 50

namespace cleaner
{
	PVOID g_KernelBase = NULL;
	ULONG g_KernelSize = 0;
	ERESOURCE PsLoadedModuleResource;

	typedef struct _MM_UNLOADED_DRIVER
	{
		UNICODE_STRING 	Name;
		PVOID 			ModuleStart;
		PVOID 			ModuleEnd;
		ULONG64 		UnloadTime;
	} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	PMM_UNLOADED_DRIVER MmUnloadedDrivers;
	PULONG MmLastUnloadedDriver;

	BOOLEAN DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask) if (*szMask == 'x' && *pData != *bMask) return 0;
		return (*szMask) == 0;
	}

	UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
	{
		for (UINT64 i = 0; i < dwLen; i++) if (DataCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (UINT64)(dwAddress + i);
		return 0;
	}

	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

		return ResolvedAddr;
	}

	NTSTATUS PatternScan(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
	{
		ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
		if (ppFound == NULL || pattern == NULL || base == NULL) return STATUS_INVALID_PARAMETER;

		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}
			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	PVOID GetKernelBase(OUT PULONG pSize)
	{
		NTSTATUS status = STATUS_SUCCESS;
		ULONG bytes = 0;
		PRTL_PROCESS_MODULES pMods = NULL;
		PVOID checkPtr = NULL;
		UNICODE_STRING routineName;

		if (g_KernelBase != NULL)
		{
			if (pSize) *pSize = g_KernelSize;
			return g_KernelBase;
		}

		RtlUnicodeStringInit(&routineName, L"NtOpenFile");

		checkPtr = MmGetSystemRoutineAddress(&routineName);
		if (checkPtr == NULL) return NULL;

		status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

		if (bytes == 0) return NULL;

		pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
		RtlZeroMemory(pMods, bytes);

		status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

		if (NT_SUCCESS(status))
		{
			PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;
			for (ULONG i = 0; i < pMods->NumberOfModules; i++)
			{
				if (checkPtr >= pMod[i].ImageBase && checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
				{
					g_KernelBase = pMod[i].ImageBase;
					g_KernelSize = pMod[i].ImageSize;
					if (pSize) *pSize = g_KernelSize;
					break;
				}
			}
		}

		if (pMods) ExFreePoolWithTag(pMods, 0x504D5448);

		return g_KernelBase;
	}

	NTSTATUS ScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
	{
		ASSERT(ppFound != NULL);
		if (ppFound == NULL) return STATUS_INVALID_PARAMETER;

		PVOID base = GetKernelBase(NULL);
		if (!base) return STATUS_NOT_FOUND;

		PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
		if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

		PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
		for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
		{
			ANSI_STRING s1, s2;
			RtlInitAnsiString(&s1, section);
			RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
			if (RtlCompareString(&s1, &s2, TRUE) == 0)
			{
				PVOID ptr = NULL;
				NTSTATUS status = PatternScan(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
				if (NT_SUCCESS(status)) *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);
				return status;
			}
		}
		return STATUS_NOT_FOUND;
	}

	BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
	{
		UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
		UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

		PVOID PiDDBLockPtr = NULL;
		if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (&PiDDBLockPtr)))) return FALSE;
		RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

		PVOID PiDTablePtr = NULL;
		if (!NT_SUCCESS(ScanSection("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (&PiDTablePtr)))) return FALSE;
		RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);

		UINT64 RealPtrPIDLock = NULL;
		RealPtrPIDLock = (UINT64)g_KernelBase + (UINT64)PiDDBLockPtr;
		*lock = (PERESOURCE)ResolveRelativeAddress((PVOID)RealPtrPIDLock, 3, 7);

		UINT64 RealPtrPIDTable = NULL;
		RealPtrPIDTable = (UINT64)g_KernelBase + (UINT64)PiDTablePtr;
		*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress((PVOID)RealPtrPIDTable, 3, 7));

		return TRUE;
	}

	LONG ClearPiDDBCacheTable()
	{
		PERESOURCE PiDDBLock = NULL;
		PRTL_AVL_TABLE PiDDBCacheTable = NULL;
		if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) return 1;

		PIDCacheobj iqvw64e;
		iqvw64e.DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
		iqvw64e.TimeDateStamp = 0x5284F8FA;

		ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

		PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &iqvw64e);
		if (pFoundEntry == NULL)
		{
			ExReleaseResourceLite(PiDDBLock);
			return 2;
		}
		else
		{
			RemoveEntryList(&pFoundEntry->List);
			RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
			ExReleaseResourceLite(PiDDBLock);
			return 0;
		}
		return 3;
	}

	LONG RetrieveMmUnloadedDriversData(VOID)
	{
		ULONG bytes = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
		if (!bytes) return 1;
		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
		status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
		if (!NT_SUCCESS(status)) return 2;
		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
		UINT64 ntoskrnlBase = 0, ntoskrnlSize = 0;
		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			if (!strcmp((char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe"))
			{
				ntoskrnlBase = (UINT64)module[i].ImageBase;
				ntoskrnlSize = (UINT64)module[i].ImageSize;
				break;
			}
		}
		if (modules) ExFreePoolWithTag(modules, 0);

		UINT64 MmUnloadedDriversInstr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");
		if (MmUnloadedDriversInstr == NULL) return 3;

		UINT64 MmLastUnloadedDriverInstr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32", "xx????xxx");
		if (MmLastUnloadedDriverInstr == NULL) return 4;
		MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)MmUnloadedDriversInstr, 3, 7);
		MmLastUnloadedDriver = (PULONG)ResolveRelativeAddress((PVOID)MmLastUnloadedDriverInstr, 2, 6);
		return 0;
	}

	BOOLEAN IsUnloadedDriverEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry)
	{
		if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
			return TRUE;
		else
			return FALSE;
	}

	BOOLEAN IsMmUnloadedDriversFilled(VOID)
	{
		for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (IsUnloadedDriverEntryEmpty(Entry)) return FALSE;
		}
		return TRUE;
	}

	LONG ClearMmUnloadedDrivers(_In_ PUNICODE_STRING DriverName, _In_ BOOLEAN AccquireResource)
	{
		if (AccquireResource) ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
		BOOLEAN Modified = FALSE;
		BOOLEAN Filled = IsMmUnloadedDriversFilled();
		for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (Modified)
			{
				PMM_UNLOADED_DRIVER PrevEntry = &MmUnloadedDrivers[Index - 1];
				RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));
				if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			}
			else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE))
			{
				PVOID BufferPool = Entry->Name.Buffer;
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
				ExFreePoolWithTag(BufferPool, 0x504D5448);
				*MmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *MmLastUnloadedDriver) - 1;
				Modified = TRUE;
			}
		}
		if (Modified)
		{
			ULONG64 PreviousTime = 0;
			for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index)
			{
				PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
				if (IsUnloadedDriverEntryEmpty(Entry)) continue;
				if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) Entry->UnloadTime = PreviousTime - 48;
				PreviousTime = Entry->UnloadTime;
			}
			ClearMmUnloadedDrivers(DriverName, FALSE);
		}
		if (AccquireResource) ExReleaseResourceLite(&PsLoadedModuleResource);
		return Modified ? 0 : 1;
	}
}