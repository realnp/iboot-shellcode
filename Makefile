TARGET = limera1n-shellcode.bin

all : $(TARGET)

$(TARGET) : limera1n-shellcode.o
	arm-none-eabi-objcopy -O binary $< $(TARGET)

limera1n-shellcode.o : limera1n-shellcode.S
	arm-none-eabi-as -mthumb --fatal-warnings -o limera1n-shellcode.o $<

clean : 
	rm $(TARGET) limera1n-shellcode.o
	
