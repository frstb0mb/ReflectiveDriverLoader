#include <ntifs.h>
#include "pe.h"
#include "PELoader.hpp"
#include "Thread.hpp"
#include "../common/ioctl.hpp"

NTSTATUS DefaultDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

PVOID base = nullptr;
PDRIVER_UNLOAD Unload = nullptr;
DRIVER_OBJECT drvobj = {};
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;

	static PVOID entry = nullptr;
	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_LOADER_LOAD_FROM_FILE:
		{
			auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
			if (!size || size >= 1024) {
				status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			if (!entry && !base) {
				auto path = reinterpret_cast<wchar_t*>(Irp->AssociatedIrp.SystemBuffer);
				if (!LoadFromFile(path, entry, base))
					status = STATUS_UNSUCCESSFUL;
			}
			else
				status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		case IOCTL_LOADER_UNLOAD:
			if (base) {
				if (Unload) {
					CallDriverUnload(DeviceObject, Unload, &drvobj);
				}
				ExFreePool(base);
				base = nullptr;
				entry = nullptr;
				memset(&drvobj, 0, sizeof(drvobj));
			}
			break;
		case IOCTL_LOADER_EXEC:
			if (entry && !drvobj.DriverUnload) {
				status = CallDriverEntry(DeviceObject, reinterpret_cast<PDRIVER_INITIALIZE>(entry), &drvobj);
				if (NT_SUCCESS(status))
					Unload = drvobj.DriverUnload;
			}
			else {
				status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

PDEVICE_OBJECT devobj = nullptr;
UNICODE_STRING lnkname = RTL_CONSTANT_STRING(L"\\??\\DriverLoader");
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	if (base) {
		if (Unload)
			Unload(&drvobj);
		ExFreePool(base);
	}
	IoDeleteSymbolicLink(&lnkname);
	IoDeleteDevice(devobj);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	
	for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DefaultDispatcher;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;

	UNICODE_STRING devname = RTL_CONSTANT_STRING(L"\\Device\\DriverLoader");
	auto status = IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&lnkname, &devname);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(devobj);
		return status;
	}

	return STATUS_SUCCESS;
}