all:
	gcc -Wall sendRaw.c -o sendRaw
	gcc -Wall sendRawGk.c -o sendRawGk
clean:
	rm -f sendRaw
