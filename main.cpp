#include "mem.h"
#include "cleaner.h"
#include "imports.h"

INT64(__fastcall* Qword_ptrOriginal)(PVOID, PVOID, PVOID, PVOID, PVOID);

INT64 __fastcall NtSetCompositionSurfaceAnalogExclusive(PVOID a1, PVOID a2, PVOID SectionInfo, PVOID a4, PVOID a5)
{
	if (ExGetPreviousMode() != UserMode)
	{
		return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
	}

	//	Printf("[>] Called\n");

	if (SectionInfo)
	{
		MEMORY_STRUCT* m = (MEMORY_STRUCT*)SectionInfo;

		if (m->magic != 0x1337)
		{
			return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
		}

		if (!m->type)
		{
			return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
		}

		//Printf("[>] m->type %x\n",m->type);

		if (m->type == 1)
		{

			//Simple check to know if the driver is available

			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				m->output = (void*)0x9999;
				//Printf("Checking if we're attached! %x", m->output);
			}

			return 9999;
		}
		else if (m->type == 2)
		{
			//Clear PiDDBCacheTable
			return cleaner::ClearPiDDBCacheTable();
		}
		else if (m->type == 3)
		{
			Printf("Read Check 1\n");
			//Read process memory
			if (!m->address || !m->size || !m->usermode_pid || !m->target_pid) return STATUS_INVALID_PARAMETER_1;

			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				Printf("Read Check 2\n");
				PEPROCESS target_process;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->target_pid, &target_process)))
				{
					Printf("Read Check 3\n");
					SIZE_T bytes = 0;

					/*if (!MmIsAddressValid((PVOID)m->address))
					{
						Printf("Read Check 4 %llx \n", (ULONG64)m->address);
						m->output = 0x00;
						return 1;
					}*/

					NTSTATUS x = MmCopyVirtualMemory(target_process, m->address, usermode_process, m->output, m->size, UserMode, &bytes);

					if (NT_SUCCESS(x))
					{
						Printf("Read Check 5\n");
						return 0;
					}
					else
						return 1;
				}
				else return 2;
			}
			else return 3;
		}
		else if (m->type == 5 || m->type == 6 || m->type == 10 || m->type == 11 || m->type == 12 || m->type == 13 || m->type == 14 || m->type == 15 || m->type == 16 || m->type == 17 || m->type == 18 || m->type == 19  || m->type == 20)
		{
			ANSI_STRING x;
			UNICODE_STRING game_module;
			RtlInitAnsiString(&x, m->type == 5 ? "r5apex.exe" : (m->type == 6 ? "RainbowSix.exe" : (m->type == 10 ? "PUBGLite-Win64-Shipping.exe" : (m->type == 11 ? "TslGame.exe" : (m->type == 12 ? "DeadByDaylight-Win64-Shipping.exe" : (m->type == 13 ? "RustClient.exe" : (m->type == 14 ? "Unityplayer.dll" : (m->type == 15 ? "GameAssembly.dll" : (m->type == 16 ? "EscapeFromTarkov.exe" : (m->type == 17 ? "FortniteClient-Win64-Shipping.exe" : ( m->type == 18 ? "RogueCompany.exe" : ( m->type == 19 ? "Scavenger-Win64-Shipping.exe" : "SCUM.exe"))))))))))));
			RtlAnsiStringToUnicodeString(&game_module, &x, TRUE);

			PEPROCESS usermode;
			PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode);

			ULONG64 base_address = NULL;
			base_address = mem::GetModuleBaseFor64BitProcess(usermode, game_module);
			m->base_address = base_address;
			RtlFreeUnicodeString(&game_module);

			return 0;
		}
		else if (m->type == 7)
		{
			//Write process memory
			if (!m->address || !m->size || !m->output || !m->usermode_pid || !m->target_pid) return STATUS_INVALID_PARAMETER_1;

			PEPROCESS usermode_process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
			{
				PEPROCESS target_process;
				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->target_pid, &target_process)))
				{
					SIZE_T bytes = 0;

					NTSTATUS x = MmCopyVirtualMemory(usermode_process, m->output, target_process, m->address, m->size, UserMode, &bytes);

					if (NT_SUCCESS(x))
						return 0;
					else
						return 1;
				}
				else return 2;
			}
			else return 3;
		}
		else if (m->type == 8)
		{
			//Call this before calling the next function
			return cleaner::RetrieveMmUnloadedDriversData();
		}
		else if (m->type == 9)
		{
			//Clear MmUnloadedDrivers list
			UNICODE_STRING iqvw64e = RTL_CONSTANT_STRING(L"iqvw64e.sys");
			return cleaner::ClearMmUnloadedDrivers(&iqvw64e, true);
		}
		else
		{
			return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
		}

	}

	return Qword_ptrOriginal(a1, a2, SectionInfo, a4, a5);
	//return -1;
}

extern "C" NTSTATUS Main(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObj);
	UNREFERENCED_PARAMETER(RegistryPath);

	//Hook the function to NtSetCompositionSurfaceAnalogExclusive
	//mem::Hook(&NtSetCompositionSurfaceAnalogExclusive);


	auto wink32base = mem::GetSystemBaseModule("\\SystemRoot\\System32\\win32kbase.sys");

	if (wink32base)
	{
		auto dataPtr = cleaner::FindPattern((UINT64)wink32base, (UINT64)0xFFFFFFFFFF, (BYTE*)"\x74\x20\x48\x8B\x44\x24\x00\x44", "xxxxxx?x");

		if (dataPtr)
		{
			UINT64 qword_ptr_derf = (UINT64)(dataPtr)-0xA;

			qword_ptr_derf = (UINT64)qword_ptr_derf + *(PINT)((PBYTE)qword_ptr_derf + 3) + 7; //6

			auto RVA = qword_ptr_derf - (UINT64)wink32base;

			Printf("dataPtr 0x%llx, qword_ptr_derf 0x%llx RVA 0x%llx\n", dataPtr, qword_ptr_derf, RVA);

			PEPROCESS Target;
			NTSTATUS Status;

			if (NT_SUCCESS(Status = mem::FindProcessByName("explorer.exe", &Target)))
			{
				if (Target)
				{
					KeAttachProcess(Target);

					*(PVOID*)&Qword_ptrOriginal = InterlockedExchangePointer((PVOID*)qword_ptr_derf, (PVOID)NtSetCompositionSurfaceAnalogExclusive);

					KeDetachProcess();
				}
				else
				{
					Printf("Error! Target == NULL");
				}
			}
			else
			{
				Printf("Error! explorer.exe not found! Status : 0x%x", Status);
			}


		}
		else
		{
			Printf("Error! ApiSetEditionGetUserObjectInformationEntryPoint not found!\n");
		}
	}
	else
	{
		Printf("Error! Win32kbase not found!\n");

	}


	Printf("HOOKED\n");
	return STATUS_SUCCESS;
}