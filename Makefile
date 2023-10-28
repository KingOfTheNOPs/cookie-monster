all:
	x86_64-w64-mingw32-gcc -c cookie-monster-bof.c -o cookie-monster-bof.o
	x86_64-w64-mingw32-strip --strip-unneeded cookie-monster-bof.o 	
	x86_64-w64-mingw32-gcc -c cookie-monster.c -o cookie-monster.exe -lshlwapi -lcrypt32
clean:
	rm cookie-monster.o
	rm cookie-monster.exe 