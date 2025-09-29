# Makefile for building cookie-monster BOF and wrapper

.PHONY: all bof wrapper clean

all: bof wrapper

bof:
	x86_64-w64-mingw32-gcc -c cookie-monster-bof.c -o cookie-monster-bof.x64.o
	x86_64-w64-mingw32-strip --strip-unneeded cookie-monster-bof.x64.o
	i686-w64-mingw32-gcc -c cookie-monster-bof.c -o cookie-monster-bof.x86.o

exe:
	x86_64-w64-mingw32-gcc cookie-monster-exe.c -o cookie-monster.exe -lkernel32 -lmsvcrt -lcrypt32 -lole32 -lws2_32 -lntdll -lncrypt -loleaut32

clean:
	rm -f cookie-monster-bof.x64.o cookie-monster-bof.x86.o cookie-monster.exe
