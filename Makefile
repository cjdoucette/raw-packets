all:
	gcc -Wall sendRaw.c -o sendRaw
	gcc -Wall sendRawGk.c -o sendRawGk
	gcc -Wall calibrateGk.c -o calibrateGk
clean:
	rm -f sendRaw sendRawGk calibrateGk
