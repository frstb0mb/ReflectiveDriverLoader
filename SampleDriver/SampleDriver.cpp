#include <wdm.h>

NTSTATUS DefaultDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ReadDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	DbgPrint("ReadDispatcher");

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	if (stack->Parameters.Read.Length >= 4) {
		*reinterpret_cast<ULONG*>(Irp->AssociatedIrp.SystemBuffer) = 'PXE';
		status = STATUS_SUCCESS;
	}
	else
		status = STATUS_INVALID_PARAMETER;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 3;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

PDEVICE_OBJECT devobj = nullptr;
UNICODE_STRING lnkname = RTL_CONSTANT_STRING(L"\\??\\Exp");
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("DriverUnload");

	IoDeleteSymbolicLink(&lnkname);
	IoDeleteDevice(devobj);
}

extern "C" DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("DriverEntry");
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DefaultDispatcher;
	DriverObject->MajorFunction[IRP_MJ_READ] = ReadDispatcher;

	UNICODE_STRING devname = RTL_CONSTANT_STRING(L"\\Device\\Exp");
	auto status = IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devobj);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	devobj->Flags |= DO_BUFFERED_IO;

	status = IoCreateSymbolicLink(&lnkname, &devname);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(devobj);
		return status;
	}

	DbgPrint("DriverEntry is Success");
	return STATUS_SUCCESS;
}