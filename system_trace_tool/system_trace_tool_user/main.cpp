#include <windows.h>

#define CLEAR_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

typedef struct _handle_information
{
	wchar_t name[100];
	unsigned long stamp;
}handle_information, * phandle_information;

bool clear_trace(const wchar_t* name, unsigned long stamp)
{
	HANDLE h = CreateFileA("\\\\.\\driver_trace", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (h == INVALID_HANDLE_VALUE) return false;

	handle_information info{ 0 };
	info.stamp = stamp;
	if (wcslen(name) < 100) wcscpy_s(info.name, name);

	DWORD r = 0;
	BOOL ret = DeviceIoControl(h, CLEAR_TRACE, &info, sizeof(info), 0, 0, &r, 0);

	CloseHandle(h);
	return ret == TRUE;
}

int main(int argc, char* argv[])
{
	clear_trace(L"the_smbois.sys", 0x611FACE5);
	system("pause");
	return 0;
}