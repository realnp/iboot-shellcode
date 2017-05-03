Contains shellcodes usable for iBoot / SecureROM exploitation. This repository is created for security researchers
interested in iBoot internals. If you don't know how to use the provided code, please don't ask me. I will not provide any 
tutorials here.

#TODO
1. limera1n shellcodes for earlier SecureROM versions
2. Test S5L8930x limera1n shellcode with various AES key sizes and images (only tested with some RELEASE and DEVELOPMENT iBSS)
3. Better validation of cryptState IMG3 keybag field

#Compilation
arm-none-eabi-as -mthumb --fatal-warnings -o shellcode.o shellcode.S && arm-none-eabi-objcopy -O binary -o shellcode.bin shellcode.o
