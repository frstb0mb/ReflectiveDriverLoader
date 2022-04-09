#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <string>
#include "../common/ioctl.hpp"

int main()
{
	auto dev = CreateFileW(L"\\\\.\\DriverLoader", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (dev == INVALID_HANDLE_VALUE) {
		printf("CreateFileW %x\n", GetLastError());
		return 0;
	}

	wchar_t filepath[] = L"C:\\users\\smith\\desktop\\SampleDriver.sys"; // Specify a driver path
	DWORD retsize = 0;
	DeviceIoControl(dev, IOCTL_LOADER_LOAD_FROM_FILE, filepath, sizeof(filepath), nullptr, 0, &retsize, nullptr);
	DeviceIoControl(dev, IOCTL_LOADER_EXEC, nullptr, 0, nullptr, 0, &retsize, nullptr);

	auto exp = CreateFileW(L"\\\\.\\Exp", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (exp == INVALID_HANDLE_VALUE) {
		printf("CreateFileW %x\n", GetLastError());
		return 0;
	}

	char buf[10] = {};
	DWORD size = 0;
	if (!ReadFile(exp, buf, sizeof(buf), &size, nullptr)) { 
		printf("ReadFile %x\n", GetLastError());
	}
	printf("%s\n", buf); // EXP
	CloseHandle(exp);

	/*
	// Reload
	DeviceIoControl(dev, IOCTL_LOADER_UNLOAD, nullptr, 0, nullptr, 0, &retsize, nullptr);
	DeviceIoControl(dev, IOCTL_LOADER_LOAD_FROM_FILE, filepath, sizeof(filepath), nullptr, 0, &retsize, nullptr);
	DeviceIoControl(dev, IOCTL_LOADER_EXEC, nullptr, 0, nullptr, 0, &retsize, nullptr);
	exp = CreateFileW(L"\\\\.\\Exp", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (exp == INVALID_HANDLE_VALUE) {
		printf("CreateFileW %x\n", GetLastError());
		return 0;
	}

	size = 0;
	if (!ReadFile(exp, buf, sizeof(buf), &size, nullptr)) {
		printf("ReadFile %x\n", GetLastError());
	}
	printf("%s\n", buf); // EXP

	CloseHandle(exp);
	*/
	CloseHandle(dev);
	
	return 0;
}