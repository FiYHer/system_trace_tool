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

typedef struct _hash_bucket_entry
{
	struct _hash_bucket_entry* next;
	UNICODE_STRING name;
	ULONG hash[5];
} hash_bucket_entry, * phash_bucket_entry;

namespace trace
{
	bool clear_cache(const wchar_t* name, unsigned long stamp)
	{
		bool status = false;

		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
		DbgPrintEx(0, 0, "[%s] ntoskrnl address 0x%llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);
		if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return status;

		/*
		 * PpCheckInDriverDatabase proc near
		 * 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 8C
		 * lea     rcx, PiDDBLock  ; Resource
		 * call    ExAcquireResourceExclusiveLite
		 * mov     r9, [rsp+58h+arg_28]
		 * lea     rcx, [rsp+58h+var_28]
		 * mov     rdx, rsi
		 */
		unsigned long long PiDDBLock = utils::find_pattern_image(ntoskrnl_address,
			"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C",
			"xxx????x????xxx");
		if (PiDDBLock == 0) return status;
		PiDDBLock = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBLock) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBLock) + 3));
		DbgPrintEx(0, 0, "[%s] PiDDBLock address 0x%llx\n", __FUNCTION__, PiDDBLock);

		/*
		 * PiLookupInDDBCache proc near
		 * 66 03 D2 48 8D 0D
		 * add     dx, dx
		 * lea     rcx, PiDDBCacheTable
		 * mov     [rsp+88h+var_58], dx
		 * mov     [rsp+88h+var_56], dx
		 */
		unsigned long long PiDDBCacheTable = utils::find_pattern_image(ntoskrnl_address,
			"\x66\x03\xD2\x48\x8D\x0D",
			"xxxxxx");
		if (PiDDBCacheTable == 0) return status;
		PiDDBCacheTable += 3;
		PiDDBCacheTable = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBCacheTable) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBCacheTable) + 3));
		DbgPrintEx(0, 0, "[%s] PiDDBCacheTable address 0x%llx \n", __FUNCTION__, PiDDBCacheTable);

		piddb_cache_entry in_entry{ };
		in_entry.stamp = stamp;
		RtlInitUnicodeString(&in_entry.name, name);

		if (ExAcquireResourceExclusiveLite((PERESOURCE)PiDDBLock, TRUE))
		{
			ppiddb_cache_entry ret_entry = (ppiddb_cache_entry)RtlLookupElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, &in_entry);
			if (ret_entry)
			{
				DbgPrintEx(0, 0, "[%s] found %ws driver cache 0x%p \n", __FUNCTION__, ret_entry->name.Buffer, ret_entry->status);

				// ָ�����
				PLIST_ENTRY prev = ret_entry->list.Blink;	// ָ����һ��
				PLIST_ENTRY next = ret_entry->list.Flink;	// ָ����һ��
				if (prev && next)
				{
					prev->Flink = next;
					next->Blink = prev;
				}

				if (RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, ret_entry))
				{
					PRTL_AVL_TABLE avl = ((PRTL_AVL_TABLE)PiDDBCacheTable);
					if (avl->DeleteCount > 0) avl->DeleteCount--;

					status = true;
				}
			}

			ExReleaseResourceLite((PERESOURCE)PiDDBLock);
		}

		return status;
	}

	bool clear_unloaded_driver(const wchar_t* name)
	{
		bool status = false;

		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
		DbgPrintEx(0, 0, "[%s] ntoskrnl address 0x%llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);
		if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return status;

		/*
		 * MmLocateUnloadedDriver proc near
		 * 4C 8B 15 ? ? ? ? 4C 8B C9
		 * mov     r10, cs:MmUnloadedDrivers
		 * mov     r9, rcx
		 * test    r10, r10
		 * jz      short loc_1402C4573
		 */
		unsigned long long MmUnloadedDrivers = utils::find_pattern_image(ntoskrnl_address,
			"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
			"xxx????xxx");
		if (MmUnloadedDrivers == 0) return status;
		MmUnloadedDrivers = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmUnloadedDrivers) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmUnloadedDrivers) + 3));
		DbgPrintEx(0, 0, "[%s] MmUnloadedDrivers address 0x%llx\n", __FUNCTION__, MmUnloadedDrivers);

		/*
		 * MiRememberUnloadedDriver proc near
		 * 8B 05 ? ? ? ? 83 F8 32
		 * mov     eax, cs:MmLastUnloadedDriver
		 * cmp     eax, 32h
		 * jnb     loc_140741D32
		 */
		unsigned long long MmLastUnloadedDriver = utils::find_pattern_image(ntoskrnl_address,
			"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
			"xx????xxx");
		if (MmLastUnloadedDriver == 0) return status;
		MmLastUnloadedDriver = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 6 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 2));
		DbgPrintEx(0, 0, "[%s] MmLastUnloadedDriver address 0x%llx \n", __FUNCTION__, MmLastUnloadedDriver);

		punloader_information unloaders = *(punloader_information*)MmUnloadedDrivers;
		unsigned long* unloaders_count = (unsigned long*)MmLastUnloadedDriver;
		if (MmIsAddressValid(unloaders) == FALSE || MmIsAddressValid(unloaders_count) == FALSE) return status;

		static ERESOURCE PsLoadedModuleResource;
		if (ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE))
		{
			for (unsigned long i = 0; i < *unloaders_count && i < max_unloader_driver; i++)
			{
				unloader_information& t = unloaders[i];
				const wchar_t* sys = t.name.Buffer;

				DbgPrintEx(0, 0, "[%s] %.2d %ws \n", __FUNCTION__, i, sys);
				if (wcsstr(sys, name))
				{
					DbgPrintEx(0, 0, "[%s] found unloader %ws driver \n", __FUNCTION__, t.name.Buffer);

					t.module_start = (void*)((unsigned long long)t.module_start + 0x1234);
					t.module_end = (void*)((unsigned long long)t.module_end - 0x123);
					t.unload_time += 0x20;
					utils::random_wstring(t.name.Buffer, t.name.Length / 2 - 4);

					DbgPrintEx(0, 0, "[%s] random string is %ws \n", __FUNCTION__, t.name.Buffer);
					status = true;
				}
			}

			ExReleaseResourceLite(&PsLoadedModuleResource);
		}

		return status;
	}

	bool clear_hash_bucket_list(const wchar_t* name)
	{
		bool status = false;

		unsigned long long ci_address = 0;
		unsigned long ci_size = 0;
		utils::get_module_base_address("CI.dll", ci_address, ci_size);
		DbgPrintEx(0, 0, "[%s] ci address 0x%llx, size %ld\n", __FUNCTION__, ci_address, ci_size);
		if (ci_address == 0 || ci_size == 0) return status;

		unsigned long long HashCacheLock = 0;

		/*
		 * I_SetSecurityState proc near
		 * 48 8B 1D ? ? ? ? EB ? F7 43 40 00 20 00
		 * mov     rbx, cs:g_KernelHashBucketList
		 * jmp     short loc_1C0073C2C
		 */
		unsigned long long KernelHashBucketList = utils::find_pattern_image(ci_address,
			"\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00",
			"xxx????x?xxxxxxx");
		if (KernelHashBucketList == 0) return status;
		else HashCacheLock = KernelHashBucketList - 0x13;

		KernelHashBucketList = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(KernelHashBucketList) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(KernelHashBucketList) + 3));
		DbgPrintEx(0, 0, "[%s] g_KernelHashBucketList address 0x%llx\n", __FUNCTION__, KernelHashBucketList);

		/*
		 * I_SetSecurityState proc near
		 * 48 8D 0D ? ? ? ? 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 48 8B 1D ? ? ? ? EB
		 * lea     rcx, g_HashCacheLock ; Resource
		 * call    cs:__imp_ExAcquireResourceExclusiveLite
		 * nop     dword ptr [rax+rax+00h]
		 * mov     rbx, cs:g_KernelHashBucketList
		 */
		HashCacheLock = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(HashCacheLock) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(HashCacheLock) + 3));
		DbgPrintEx(0, 0, "[%s] g_HashCacheLock address 0x%llx\n", __FUNCTION__, HashCacheLock);

		if (ExAcquireResourceExclusiveLite((PERESOURCE)HashCacheLock, TRUE))
		{
			phash_bucket_entry current_entry = ((phash_bucket_entry)KernelHashBucketList)->next;
			phash_bucket_entry prev_entry = (phash_bucket_entry)KernelHashBucketList;

			UNICODE_STRING drv_name;
			RtlInitUnicodeString(&drv_name, name);

			while (current_entry)
			{
				DbgPrintEx(0, 0, "[%s] %ws 0x%x\n", __FUNCTION__, current_entry->name.Buffer, current_entry->hash[0]);

				if (wcsstr(current_entry->name.Buffer, name))
				{
					DbgPrintEx(0, 0, "[%s] found %ws driver \n", __FUNCTION__, current_entry->name.Buffer);

					// ָ�����
					prev_entry->next = current_entry->next;

					// ָ���������ͷ��ڴ��ˣ��α�ִ����Щ����?
					current_entry->hash[0] = current_entry->hash[1] = 1;
					current_entry->hash[2] = current_entry->hash[3] = 1;
					utils::random_wstring(current_entry->name.Buffer, current_entry->name.Length / 2 - 4);

					ExFreePoolWithTag(current_entry, 0);
					status = true;
					break;
				}
				else
				{
					prev_entry = current_entry;
					current_entry = current_entry->next;
				}
			}

			ExReleaseResourceLite((PERESOURCE)HashCacheLock);
		}

		return status;
	}

	bool clear_ci_ea_cache_lookaside_list()
	{
		bool status = false;

		unsigned long long ci_address = 0;
		unsigned long ci_size = 0;
		utils::get_module_base_address("CI.dll", ci_address, ci_size);
		DbgPrintEx(0, 0, "[%s] ci address 0x%llx, size %ld\n", __FUNCTION__, ci_address, ci_size);
		if (ci_address == 0 || ci_size == 0) return status;

		/*
		 * CiInitializePhase2 proc near
		 * 8B 15 ? ? ? ? 48 8B 05 ? ? ? ? 44 8B 05 ? ? ? ? 8B 0D ? ? ? ? FF 05 ? ? ? ? FF 15
		 * lea     rcx, g_CiEaCacheLookasideList ; ListHead
		 * call    cs:__imp_ExpInterlockedPopEntrySList
		 * nop     dword ptr [rax+rax+00h]
		 * mov     rsi, rax
		 * test    rax, rax
		 * jnz     short loc_1C0044EB8
		 * mov     edx, cs:g_CiEaCacheLookasideList.L.Size
		 * mov     rax, cs:g_CiEaCacheLookasideList.L.Allocate
		 * mov     r8d, cs:g_CiEaCacheLookasideList.L.Tag
		 * mov     ecx, cs:g_CiEaCacheLookasideList.L.Type
		 * inc     dword ptr cs:g_CiEaCacheLookasideList.L.anonymous_0
		 */
		unsigned long long CiEaCacheLookasideList = utils::find_pattern_image(ci_address,
			"\x8B\x15\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x44\x8B\x05\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\xFF\x05\x00\x00\x00\x00\xFF\x15",
			"xx????xxx????xxx????xx????xx????xx");
		if (CiEaCacheLookasideList == 0) return status;
		CiEaCacheLookasideList -= 0x1B;
		CiEaCacheLookasideList = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 3));
		DbgPrintEx(0, 0, "[%s] g_CiEaCacheLookasideList address 0x%llx\n", __FUNCTION__, CiEaCacheLookasideList);

		PLOOKASIDE_LIST_EX g_CiEaCacheLookasideList = (PLOOKASIDE_LIST_EX)CiEaCacheLookasideList;
		ULONG size = g_CiEaCacheLookasideList->L.Size;
		ExDeleteLookasideListEx(g_CiEaCacheLookasideList);
		if (NT_SUCCESS(ExInitializeLookasideListEx(g_CiEaCacheLookasideList, NULL, NULL, PagedPool, 0, size, 'csIC', 0)))
		{
			DbgPrintEx(0, 0, "[%s] clear g_CiEaCacheLookasideList \n", __FUNCTION__);
			status = true;
		}

		return status;
	}
}