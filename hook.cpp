#include <windows.h>

typedef bool(WINAPI* defCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef bool(WINAPI* defCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

FARPROC orig_CreateFileA = 0;
FARPROC orig_CreateFileW = 0;

bool hooked_CreateFileA(LPCSTR fileName, DWORD b, DWORD c, LPSECURITY_ATTRIBUTES d, DWORD e, DWORD f, HANDLE g)
{
	if (!strcmp(fileName, "\\\\.\\PhysicalDrive0"))
	{
		Beep(1000, 1000);
		return false;
	}

	else if (!strcmp(fileName, "\\\\.\\C:"))
	{
		Beep(1500, 1000);
		return false;
	}

	else if (!strcmp(fileName, "C:\\Windows\\system32\\kernel32.dll")) {
		Beep(1500, 100);
		Beep(1500, 100);
		Beep(1500, 100);
		return ((defCreateFileA)orig_CreateFileA)("C:\\Windows\\System32\\user32.dll", b, c, d, e, f, g);;
	}

	return ((defCreateFileA)orig_CreateFileA)(fileName, b, c, d, e, f, g);
}

bool hooked_CreateFileW(LPCWSTR fileName, DWORD b, DWORD c, LPSECURITY_ATTRIBUTES d, DWORD e, DWORD f, HANDLE g)
{
	if (!wcscmp(fileName, L"\\\\.\\PhysicalDrive0"))
	{
		Beep(1000, 1000);
		return false;
	}

	else if (!wcscmp(fileName, L"\\\\.\\C:"))
	{
		Beep(1500, 1000);
		return false;
	}

	else if (!wcscmp(fileName, L"C:\\Windows\\system32\\kernel32.dll")) {
		Beep(1500, 100);
		Beep(1500, 100);
		Beep(1500, 100);
		return ((defCreateFileW)orig_CreateFileW)(L"C:\\Windows\\System32\\user32.dll", b, c, d, e, f, g);;
	}

	return ((defCreateFileW)orig_CreateFileW)(fileName, b, c, d, e, f, g);
}

void hook_CreateFileA(FARPROC proxyAddr)
{
	unsigned long old_protection;
	void* original_func;
	int func_size = 30;

	unsigned char jmp_opcode[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

	FARPROC fp_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateFileA");
	VirtualProtect(fp_addr, 5, PAGE_EXECUTE_READWRITE, &old_protection);
	original_func = VirtualAlloc(0, func_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	orig_CreateFileA = (FARPROC)original_func;
	memcpy(original_func, fp_addr, func_size);

	*(ULONG*)(jmp_opcode + 1) = ((ULONG)proxyAddr - ((ULONG)fp_addr + 5));

	memcpy(fp_addr, jmp_opcode, 5);

	VirtualProtect(fp_addr, 5, old_protection, &old_protection);
	VirtualProtect(original_func, 5, old_protection, &old_protection);
}

void hook_CreateFileW(FARPROC proxyAddr)
{
	unsigned long old_protection;
	void* original_func;
	int func_size = 30;

	unsigned char jmp_opcode[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

	FARPROC fp_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateFileW");
	VirtualProtect(fp_addr, 5, PAGE_EXECUTE_READWRITE, &old_protection);
	original_func = VirtualAlloc(0, func_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	orig_CreateFileW = (FARPROC)original_func;
	memcpy(original_func, fp_addr, func_size);

	*(ULONG*)(jmp_opcode + 1) = ((ULONG)proxyAddr - ((ULONG)fp_addr + 5));

	memcpy(fp_addr, jmp_opcode, 5);

	VirtualProtect(fp_addr, 5, old_protection, &old_protection);
	VirtualProtect(original_func, 5, old_protection, &old_protection);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		Beep(1000, 100);
		hook_CreateFileA((FARPROC)hooked_CreateFileA);
		Sleep(100);
		Beep(1000, 100);
		hook_CreateFileW((FARPROC)hooked_CreateFileW);
	}

	return true; 
}
