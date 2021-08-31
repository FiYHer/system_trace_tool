#pragma once
#include "import.hpp"

namespace utils
{
	bool get_module_base_address(const char* name, unsigned long long& addr, unsigned long& size)
	{
		unsigned long need_size = 0;
		ZwQuerySystemInformation(11, &need_size, 0, &need_size);
		if (need_size == 0) return false;

		const unsigned long tag = 'Util';
		PSYSTEM_MODULE_INFORMATION sys_mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, need_size, tag);
		if (sys_mods == 0) return false;

		NTSTATUS status = ZwQuerySystemInformation(11, sys_mods, need_size, 0);
		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(sys_mods, tag);
			return false;
		}

		addr = 0;
		size = 0;
		for (unsigned long long i = 0; i < sys_mods->ulModuleCount; i++)
		{
			CONST SYSTEM_MODULE& mod = sys_mods->Modules[i];
			if (strstr(mod.ImageName, name))
			{
				addr = (unsigned long long)mod.Base;
				size = (unsigned long)mod.Size;
				break;
			}
		}

		ExFreePoolWithTag(sys_mods, tag);
		return addr && size;
	}

	bool pattern_check(const char* data, const char* pattern, const char* mask)
	{
		size_t len = strlen(mask);

		for (size_t i = 0; i < len; i++)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}

	unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
	{
		size -= (unsigned long)strlen(mask);

		for (unsigned long i = 0; i < size; i++)
		{
			if (pattern_check((const char*)addr + i, pattern, mask))
				return addr + i;
		}

		return 0;
	}

	unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (strstr((const char*)p->Name, ".text") || 'EGAP' == *reinterpret_cast<int*>(p->Name))
			{
				DWORD64 res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
				if (res) return res;
			}
		}

		return 0;
	}

	wchar_t* random_wstring(wchar_t* str, size_t size)
	{
		if (str)
		{
			ULONG64 time = 0;
			KeQuerySystemTime(&time);
			ULONG seed = (ULONG)time;
			static const wchar_t maps[62] = L"123456789ZXCVBNMASDFGHJKLQWERTYUIOPzxcvbnmasdfghjklqwertyuiop";

			if (size == 0) size = wcslen(str);
			for (size_t i = 0; i < size; i++) str[i] = maps[RtlRandomEx(&seed) % 60];
		}

		return str;
	}
}