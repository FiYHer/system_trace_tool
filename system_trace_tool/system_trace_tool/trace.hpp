#pragma once

constexpr unsigned int max_unloader_driver = 50;
typedef struct _unloader_information
{
	UNICODE_STRING name;
	PVOID module_start;
	PVOID module_end;
	ULONG64 unload_time;
} unloader_information, * punloader_information;

typedef struct _piddb_cache_entry
{
	LIST_ENTRY list;
	UNICODE_STRING name;
	ULONG stamp;
	NTSTATUS status;
	char _0x0028[16];
}piddb_cache_entry, * ppiddb_cache_entry;

namespace trace
{
	bool clear_cache(const wchar_t* name, unsigned long stamp)
	{
		if (name == nullptr) return false;

		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
		if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return false;
		DbgPrintEx(0, 0, "[%s] ntoskrnl address %llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);

		// lea     rcx, PiDDBLock  ; Resource
		unsigned long long PiDDBLock = utils::find_pattern_image(ntoskrnl_address,
			"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C",
			"xxx????x????xxx");
		if (PiDDBLock == 0) return false;
		PiDDBLock = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBLock) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBLock) + 3));
		DbgPrintEx(0, 0, "[%s] PiDDBLock address 0x%llx\n", __FUNCTION__, PiDDBLock);

		// lea     rcx, PiDDBCacheTable
		unsigned long long PiDDBCacheTable = utils::find_pattern_image(ntoskrnl_address,
			"\x66\x03\xD2\x48\x8D\x0D",
			"xxxxxx");
		if (PiDDBCacheTable == 0) return false;
		PiDDBCacheTable += 3;
		PiDDBCacheTable = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBCacheTable) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBCacheTable) + 3));
		DbgPrintEx(0, 0, "[%s] PiDDBCacheTable address 0x%llx \n", __FUNCTION__, PiDDBCacheTable);

		bool result = true;
		piddb_cache_entry entry{ };
		RtlInitUnicodeString(&entry.name, name);
		entry.stamp = stamp;

		ExAcquireResourceExclusiveLite((PERESOURCE)PiDDBLock, TRUE);

		ppiddb_cache_entry found = (ppiddb_cache_entry)RtlLookupElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, &entry);
		if (found)
		{
			DbgPrintEx(0, 0, "[%s] found %ws driver cache \n", __FUNCTION__, name);

			result = result && RemoveEntryList(&found->list);
			result = result && RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, found);
		}

		ExReleaseResourceLite((PERESOURCE)PiDDBLock);

		return result;
	}

	bool clear_unloaded_driver(const wchar_t* name)
	{
		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
		if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return false;
		DbgPrintEx(0, 0, "[%s] ntoskrnl address %llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);

		// mov     r10, cs:MmUnloadedDrivers
		unsigned long long MmUnloadedDrivers = utils::find_pattern_image(ntoskrnl_address,
			"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
			"xxx????xxx");
		if (MmUnloadedDrivers == 0) return false;
		MmUnloadedDrivers = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmUnloadedDrivers) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmUnloadedDrivers) + 3));
		DbgPrintEx(0, 0, "[%s] MmUnloadedDrivers address 0x%llx\n", __FUNCTION__, MmUnloadedDrivers);

		// mov     eax, cs:MmLastUnloadedDriver
		unsigned long long MmLastUnloadedDriver = utils::find_pattern_image(ntoskrnl_address,
			"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
			"xx????xxx");
		if (MmLastUnloadedDriver == 0) return false;
		MmLastUnloadedDriver = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 6 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 2));
		DbgPrintEx(0, 0, "[%s] MmLastUnloadedDriver address 0x%llx \n", __FUNCTION__, MmLastUnloadedDriver);

		punloader_information unloaders = *(punloader_information*)MmUnloadedDrivers;
		unsigned long* unloaders_count = (unsigned long*)MmLastUnloadedDriver;
		if (MmIsAddressValid(unloaders) == FALSE || MmIsAddressValid(unloaders_count) == FALSE) return false;

		static ERESOURCE PsLoadedModuleResource;
		ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);

		for (unsigned long i = 0; i < *unloaders_count && i < max_unloader_driver; i++)
		{
			unloader_information& t = unloaders[i];
			const wchar_t* sys = t.name.Buffer;

			DbgPrintEx(0, 0, "[%s] %ws \n", __FUNCTION__, sys);

			if (wcsstr(sys, name))
			{
				DbgPrintEx(0, 0, "[%s] random unloader %ws driver \n", __FUNCTION__, t.name.Buffer);

				t.module_start = (void*)((unsigned long long)t.module_start + 0x1234);
				t.module_end = (void*)((unsigned long long)t.module_end - 0x123);
				t.unload_time += 0x20;
				utils::random_wstring(t.name.Buffer, t.name.Length / 2 - 4);
			}
		}

		ExReleaseResourceLite(&PsLoadedModuleResource);

		return true;
	}
}