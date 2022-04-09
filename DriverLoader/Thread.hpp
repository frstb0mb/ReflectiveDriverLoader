#pragma once

#include <ntifs.h>
NTSTATUS CallDriverEntry(PDEVICE_OBJECT devobj, PDRIVER_INITIALIZE entry, PDRIVER_OBJECT drvobj);
void CallDriverUnload(PDEVICE_OBJECT devobj, PDRIVER_UNLOAD Unload, PDRIVER_OBJECT drvobj);