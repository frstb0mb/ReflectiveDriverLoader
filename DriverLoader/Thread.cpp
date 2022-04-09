#include <ntifs.h>

namespace
{
enum class FuncOnSystem
{
	DriverEntry,
	DriverUnload,
};

struct threadargs {
	union {
		PVOID				dummy;
		PDRIVER_INITIALIZE	DriverEntry;
		PDRIVER_UNLOAD		DriverUnload;
	};
	PDRIVER_OBJECT		DriverObject;
	PUNICODE_STRING		RegistryPath;
	NTSTATUS			retval;
	FuncOnSystem		which;
	KEVENT				event;
};


void SystemThread(PVOID StartContext)
{
	if (StartContext) {
		auto arg = reinterpret_cast<threadargs*>(StartContext);
		__try {
			switch (arg->which) {
				case FuncOnSystem::DriverEntry:
					arg->retval = arg->DriverEntry(arg->DriverObject, arg->RegistryPath);
					break;
				case FuncOnSystem::DriverUnload:
					arg->DriverUnload(arg->DriverObject);
					break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
		KeSetEvent(&arg->event, IO_NO_INCREMENT, TRUE);
	}
}

NTSTATUS CreateSystemThread(PDEVICE_OBJECT devobj, FuncOnSystem which, PVOID func, PDRIVER_OBJECT drvobj = nullptr)
{
	HANDLE thread = nullptr;
	OBJECT_ATTRIBUTES oa = {};
	InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

	UNICODE_STRING reg = RTL_CONSTANT_STRING(L"DummyReg");
	threadargs arg = { func, drvobj, &reg, STATUS_ABANDONED, which };
	KeInitializeEvent(&arg.event, SynchronizationEvent, 0);

	auto status = IoCreateSystemThread(devobj, &thread, THREAD_ALL_ACCESS, &oa,
		nullptr, nullptr, SystemThread, &arg);

	if (!NT_SUCCESS(status))
		return status;

	LARGE_INTEGER timeout = {};
	timeout.QuadPart = -10000000; // 1 sec
	KeWaitForSingleObject(&arg.event, Executive, KernelMode, FALSE, &timeout);
	ZwClose(thread);

	return arg.retval;
}
}


NTSTATUS CallDriverEntry(PDEVICE_OBJECT devobj, PDRIVER_INITIALIZE entry, PDRIVER_OBJECT drvobj)
{
	if (!devobj || !entry || !drvobj)
		return STATUS_INVALID_PARAMETER;
	auto status = CreateSystemThread(devobj, FuncOnSystem::DriverEntry, entry, drvobj);
	if (NT_SUCCESS(status)) 
		drvobj->DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

void CallDriverUnload(PDEVICE_OBJECT devobj, PDRIVER_UNLOAD unload, PDRIVER_OBJECT drvobj)
{
	if (!devobj || !unload || !drvobj)
		return;
	CreateSystemThread(devobj, FuncOnSystem::DriverUnload, unload, drvobj);
}