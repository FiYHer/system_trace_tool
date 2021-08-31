#include "utils.hpp"
#include "trace.hpp"

#define CLEAR_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

UNICODE_STRING g_device_name = RTL_CONSTANT_STRING(L"\\Device\\driver_trace");
UNICODE_STRING g_symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\driver_trace");
PDEVICE_OBJECT g_device_object = 0;

typedef struct _handle_information
{
	wchar_t name[100];
	unsigned long stamp;
}handle_information, * phandle_information;

NTSTATUS defalut_irp(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS communication_irp(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
	ULONG control = io->Parameters.DeviceIoControl.IoControlCode;
	phandle_information info = (phandle_information)irp->AssociatedIrp.SystemBuffer;

	if (info)
	{
		if (CLEAR_TRACE == control)
		{
			trace::clear_cache(info->name, info->stamp);
			trace::clear_unloaded_driver(info->name);
		}
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS create_device(PDRIVER_OBJECT driver)
{
	NTSTATUS status = IoCreateDevice(driver, 0, &g_device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	if (!NT_SUCCESS(status)) return status;

	status = IoCreateSymbolicLink(&g_symbolic_link, &g_device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_device_object);
		return status;
	}

	g_device_object->Flags |= DO_DIRECT_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) driver->MajorFunction[i] = defalut_irp;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = communication_irp;

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT)
{
	if (g_device_object != nullptr)
	{
		IoDeleteSymbolicLink(&g_symbolic_link);
		IoDeleteDevice(g_device_object);
	}
}

EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING reg)
{
	driver->DriverUnload = DriverUnload;
	return create_device(driver);
}