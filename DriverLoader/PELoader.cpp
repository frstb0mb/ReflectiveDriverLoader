#include <ntifs.h>
#include "PE.h"

extern "C" PVOID RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);

namespace
{
ULONG ZwGetFileSize(HANDLE hFile, ULONG &size)
{
	IO_STATUS_BLOCK io = {};
	FILE_STANDARD_INFORMATION info = {};
	auto status = ZwQueryInformationFile(hFile, &io, &info, sizeof(info), FileStandardInformation);
	if (NT_SUCCESS(status))
		size = info.EndOfFile.LowPart;

	return status;
}

HANDLE OpenFileFromDOSPath(wchar_t *filepath)
{
	if (!filepath)
		return nullptr;
	if (wcslen(filepath) < 3)
		return nullptr;
	// Relative Path is not supported
	if (filepath[1] != L':' || filepath[2] != L'\\')
		return nullptr;

	// Convert to NTPATH
	UNICODE_STRING loadpath = {};
	constexpr SIZE_T MAX_PATHLEN = 1024;
	loadpath.Buffer = reinterpret_cast<wchar_t*>(ExAllocatePoolWithTag(PagedPool, MAX_PATHLEN, '1GAT'));
	if (!loadpath.Buffer)
		return false;

	loadpath.MaximumLength = MAX_PATHLEN;
	if (!NT_SUCCESS(RtlAppendUnicodeToString(&loadpath, L"\\??\\")) ||
		!NT_SUCCESS(RtlAppendUnicodeToString(&loadpath, filepath)))
	{
		ExFreePool(loadpath.Buffer);
		return nullptr;
	}

	HANDLE file = nullptr;
	OBJECT_ATTRIBUTES oa = {};
	InitializeObjectAttributes(&oa, &loadpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
	IO_STATUS_BLOCK io = {};
	auto status = ZwOpenFile(&file, GENERIC_READ | SYNCHRONIZE, &oa, &io, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	ExFreePool(loadpath.Buffer);

	if (NT_SUCCESS(status))
		return file;
	else
		return nullptr;
}
}

bool LoadFromFile(wchar_t* filepath, PVOID& entry, PVOID& base)
{
	if (!filepath)
		return false;

	bool ret = false;
	HANDLE file = nullptr;
	PBYTE file_raw = nullptr;
	PBYTE imagebase = nullptr;

	// Read Target as RAW
	file = OpenFileFromDOSPath(filepath);
	if (!file)
		return false;
	

	ULONG filesize = 0;
	auto status = ZwGetFileSize(file, filesize);
	if (!NT_SUCCESS(status) || !filesize)
		goto END;
	

	file_raw = reinterpret_cast<PBYTE>(ExAllocatePoolWithTag(PagedPool, filesize, '1GAT'));
	if (!file_raw)
		goto END;
	

	{
		IO_STATUS_BLOCK io = {};
		status = ZwReadFile(file, nullptr, nullptr, nullptr, &io, file_raw, filesize, nullptr, nullptr);
		if (!NT_SUCCESS(status))
			goto END;
		
	}

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(file_raw);
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(file_raw + dos->e_lfanew);
	auto loadsize = nt->OptionalHeader.SizeOfImage;
	imagebase = reinterpret_cast<PBYTE>(ExAllocatePoolWithTag(NonPagedPoolExecute, loadsize, '1GAT'));
	if (!imagebase)
		goto END;

	base = imagebase;

	// Load Headers
	memcpy_s(imagebase, loadsize, file_raw, nt->OptionalHeader.SizeOfHeaders);

	// Load Sections
	auto secheader = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt + 1);
	auto lastaddr = imagebase + loadsize;
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		auto destaddr = imagebase + secheader[i].VirtualAddress;
		auto srcaddr = file_raw + secheader[i].PointerToRawData;
		memcpy_s(destaddr, lastaddr - destaddr, srcaddr, secheader[i].SizeOfRawData);
	}
	entry = imagebase + nt->OptionalHeader.AddressOfEntryPoint;

	// Relocation
	ULONG size = 0;
	auto relocdesc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(RtlImageDirectoryEntryToData(imagebase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size));
	if (relocdesc == nullptr)
		goto END;


	DWORD64 delta = reinterpret_cast<DWORD64>(imagebase - nt->OptionalHeader.ImageBase); // offset of between real and ideal
	while (relocdesc->VirtualAddress && relocdesc->SizeOfBlock) {
		DWORD count = (relocdesc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD list = reinterpret_cast<PWORD>(relocdesc + 1);
		for (DWORD i = 0; i < count; i++) {
			if (list[i]) {
				auto ptr = reinterpret_cast<DWORD64*>(imagebase + relocdesc->VirtualAddress + (list[i] & 0xFFF)); // remain is type but meaningless
				*ptr += delta;
			}
		}
		relocdesc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(relocdesc) + relocdesc->SizeOfBlock);
	}

	// Make IAT
	auto importdesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(RtlImageDirectoryEntryToData(imagebase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size));
	if (importdesc) {
		// Use Kernel API
		while (importdesc->Characteristics) {
			auto origfirstthunk = reinterpret_cast<PIMAGE_THUNK_DATA>(imagebase + importdesc->OriginalFirstThunk);
			auto firsthutnk = reinterpret_cast<PIMAGE_THUNK_DATA>(imagebase + importdesc->FirstThunk);
			auto modname_ascii = reinterpret_cast<char*>(imagebase + importdesc->Name);
			if (_stricmp(modname_ascii, "ntoskrnl.exe") && _stricmp(modname_ascii, "HAL.dll")) // Support only system
				goto END;

			while (origfirstthunk->u1.AddressOfData) {
				auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imagebase + origfirstthunk->u1.AddressOfData);
				LPCSTR procname_char = reinterpret_cast<LPCSTR>(ibn->Name);
				ANSI_STRING procname_ansi = {};
				RtlInitAnsiString(&procname_ansi, procname_char);
				UNICODE_STRING procname = {};
				RtlAnsiStringToUnicodeString(&procname, &procname_ansi, TRUE);

				ULONGLONG funcaddr = reinterpret_cast<ULONGLONG>(MmGetSystemRoutineAddress(&procname));
				if (!funcaddr) {
					RtlFreeUnicodeString(&procname);
					continue;
				}
				firsthutnk->u1.Function = funcaddr;

				RtlFreeUnicodeString(&procname);
				firsthutnk++;
				origfirstthunk++;
			}
			importdesc++;
		}
	}

	// Initialize cookie
	auto loadconfig = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(RtlImageDirectoryEntryToData(imagebase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size));
	if (loadconfig) {
		if (loadconfig->SecurityCookie)
			*reinterpret_cast<ULONGLONG*>(loadconfig->SecurityCookie) = 'TEST';
	}

	ret = true;

END:
	if (!ret) {
		if (imagebase)
			ExFreePool(imagebase);
		entry = nullptr;
		base = nullptr;
	}
	
	if (file_raw)
		ExFreePool(file_raw);
	ZwClose(file);

	return ret;
}