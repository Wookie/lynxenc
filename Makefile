all:
	gcc -gstabs+ -O0 lynxdec.c -o lynxdec

clean:
	rm -rf lynxdec
