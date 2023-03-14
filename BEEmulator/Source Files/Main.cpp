#include "Includes.hpp"

static uint64_t _be_pre_ob_callback_cave = 0;
static POB_PRE_OPERATION_CALLBACK _be_original_ob_callback = 0;

OB_PREOP_CALLBACK_STATUS HookCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	auto result = _be_original_ob_callback(RegistrationContext, OperationInformation);
	OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
	return result;
}

PVOID Hook_ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
{
	if (PoolType == 0x200 && NumberOfBytes == 0x1000 || PoolType == 0x200 && NumberOfBytes == 0x90)
	{
		return 0;
	}
	return ExAllocatePool(PoolType, NumberOfBytes);
}

NTSTATUS Hook_ObRegisterCallbacks(POB_CALLBACK_REGISTRATION callback_registration, PVOID* registration_handle)
{
	DbgPrintEx(0, 0, "[+] BE Called ObRegisterCallbacks\n");

	_be_original_ob_callback = callback_registration->OperationRegistration->PreOperation;
	PRTL_PROCESS_MODULES modules = Utils::GetModuleList();
	PVOID module_base{};
	PVOID module_size{};

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];

		if (!strstr((const char*)module->FullPathName, "iorate"))
		{
			continue;
		}

		_be_pre_ob_callback_cave = Utils::find_codecave(module->ImageBase, 16);

		DbgPrintEx(0, 0, "[+] Code Cave Address 0x%p\n", _be_pre_ob_callback_cave);

		if (_be_pre_ob_callback_cave != 0)
		{
			DbgPrintEx(0, 0, "[+] Code Cave Inside %s\n", module->FullPathName);

			if (!Utils::patch_codecave_detour(_be_pre_ob_callback_cave, (uint64_t)&HookCallback))
			{
				DbgPrintEx(0, 0, "[!] Failed To Patch Code Cave\n");
				return STATUS_UNSUCCESSFUL;
			}
			callback_registration->OperationRegistration->PreOperation = (POB_PRE_OPERATION_CALLBACK)_be_pre_ob_callback_cave;
			DbgPrintEx(0, 0, "[+] Patched ObRegisterCallbacks\n");
			ExFreePoolWithTag(modules, 0);
			break;
		}
	}
	return ObRegisterCallbacks(callback_registration, registration_handle);
}

PVOID Hook_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
	if (wcsstr(SystemRoutineName->Buffer, L"ObRegisterCallbacks"))
	{
		return &Hook_ObRegisterCallbacks;
	}
	else if (wcsstr(SystemRoutineName->Buffer, L"ExAllocatePool"))
	{
		return &Hook_ExAllocatePool;
	}
	return MmGetSystemRoutineAddress(SystemRoutineName);
}

NTSTATUS DriverEntry(uint64_t mdl_ptr, uint64_t image_size)
{
	/* No Point Using LoadImageNotifyRoutine */
	PVOID be_module = NULL;
	while (true)
	{
		be_module = Utils::GetSystemModuleBase(L"BEDaisy.sys");
		if (be_module != NULL) break;
	}
	if (be_module)
	{
		DbgPrintEx(0, 0, "[+] Found BEDaisy.sys -> %p\n", be_module);
		Utils::IATHook(be_module, "MmGetSystemRoutineAddress", &Hook_MmGetSystemRoutineAddress);
	}
	return STATUS_SUCCESS;
}