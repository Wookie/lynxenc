all: lynxdec rsadec

lynxdec:
	gcc -gstabs+ -O0 lynxdec.c -o lynxdec

rsadec:
	gcc -gstabs+ -O0 rsadec.c -o rsadec -l ssl

clean:
	rm -rf lynxdec
	rm -rf rsadec
