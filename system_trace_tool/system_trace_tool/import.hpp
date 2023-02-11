#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct _SYSTEM_MODULE
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	NTSTATUS ZwQuerySystemInformation(
		DWORD32 systemInformationClass,
		PVOID systemInformation,
		ULONG systemInformationLength,
		PULONG returnLength);

	NTSTATUS ObReferenceObjectByName(
		PUNICODE_STRING objectName,
		ULONG attributes,
		PACCESS_STATE accessState,
		ACCESS_MASK desiredAccess,
		POBJECT_TYPE objectType,
		KPROCESSOR_MODE accessMode,
		PVOID parseContext, PVOID* object);

	extern POBJECT_TYPE* IoDriverObjectType;


#ifdef __cplusplus
}
#endif