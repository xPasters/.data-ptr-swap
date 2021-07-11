#pragma once
#include "imports.h"

namespace mem
{
	PVOID GetSystemBaseModule(const char* module_name)
	{
		ULONG bytes = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

		if (!bytes) return 0;

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);

		status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

		if (!NT_SUCCESS(status)) return 0;

		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
		PVOID module_base = 0, module_size = 0;

		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			if (strcmp((char*)module[i].FullPathName, module_name) == 0)
			{
				module_base = module[i].ImageBase;
				module_size = (PVOID)module[i].ImageSize;
				break;
			}
		}

		if (modules) ExFreePoolWithTag(modules, 0);
		if (module_base <= 0) return 0;
		return module_base;
	}

	PVOID GetSystemBaseModuleExport(const char* module_name, LPCSTR routine_name)
	{
		PVOID base_module = mem::GetSystemBaseModule(module_name);
		if (!base_module) return NULL;
		return RtlFindExportedRoutineByName(base_module, routine_name);
	}

	bool WriteMemory(void* address, void* buffer, size_t size)
	{
		if (!RtlCopyMemory(address, buffer, size))  return false;
		else return true;
	}

	bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size) {

		PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

		if (!Mdl) return false;

		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
		PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

		WriteMemory(Mapping, buffer, size);

		MmUnmapLockedPages(Mapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return true;
	}

	bool Hook(void* destination)
	{
		if (!destination) return false;

		PVOID* dxgk_routine = reinterpret_cast<PVOID*>(mem::GetSystemBaseModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));
		if (!dxgk_routine) return false;

		BYTE orignal_shell_code[] = {
		0x90,										// nop
		0x90,										// nop 
		0x90,										// nop
		0x48, 0xB8,									// mov rax, 
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,		// [xxx]
		0x90,										// nop
		0x90,										// nop
		0x48, 0xB8,									// mov rax, 
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,		// [xxx]
		0xFF, 0xE0,									// jmp rax // d0 for call
		0xCC,										//int3									

		};

		BYTE start[]{ 0x48, 0xB8 };
		BYTE end[]{ 0xFF, 0xE0, 0xCC };

		RtlSecureZeroMemory(&orignal_shell_code, sizeof(orignal_shell_code));

		memcpy((PVOID)((ULONG_PTR)orignal_shell_code), &start, sizeof(start));

		uintptr_t test_address = reinterpret_cast<uintptr_t>(destination);

		memcpy((PVOID)((ULONG_PTR)orignal_shell_code + sizeof(start)), &test_address, sizeof(void*));
		memcpy((PVOID)((ULONG_PTR)orignal_shell_code + sizeof(start) + sizeof(void*)), &end, sizeof(end));

		WriteToReadOnlyMemory(dxgk_routine, &orignal_shell_code, sizeof(orignal_shell_code));

		return true;
	}

	ULONG64 GetModuleBaseFor64BitProcess(PEPROCESS proc, UNICODE_STRING module_name)
	{
		PPEB pPeb = PsGetProcessPeb(proc);
		if (!pPeb) return 0;

		KAPC_STATE state;

		KeStackAttachProcess(proc, &state);

		PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

		if (!pLdr)
		{
			KeUnstackDetachProcess(&state);
			return 0;
		}

		for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0)
			{
				ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
				KeUnstackDetachProcess(&state);
				return baseAddr;
			}
		}

		KeUnstackDetachProcess(&state);

		return 0;
	}


	NTSTATUS FindProcessByName(CHAR* process_name, PEPROCESS* process)
	{
		PEPROCESS sys_process = PsInitialSystemProcess;
		PEPROCESS cur_entry = sys_process;

		CHAR image_name[15];

		do
		{
			RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + 0x5a8) /*EPROCESS->ImageFileName*/, sizeof(image_name));

			if (strstr(image_name, process_name))
			{
				DWORD active_threads;
				RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + 0x5f0) /*EPROCESS->ActiveThreads*/, sizeof(active_threads));
				if (active_threads)
				{
					*process = cur_entry;
					return STATUS_SUCCESS;
				}
			}

			PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+0x448) /*EPROCESS->ActiveProcessLinks*/;
			cur_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

		} while (cur_entry != sys_process);

		return STATUS_NOT_FOUND;
	}
}