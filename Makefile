all: lynxdec rsadec privatekeytest

lynxdec: lynxdec.c keys.h loaders.h
	gcc -gstabs+ -O0 lynxdec.c -o lynxdec

rsadec: rsadec.c keys.h loaders.h
	gcc -gstabs+ -O0 rsadec.c -o rsadec -l ssl

privatekeytest: privatekeytest.c privatekeydata.h keys.h
	gcc -gstabs+ -O0 privatekeytest.c -o privatekeytest -l ssl

clean:
	rm -rf lynxdec
	rm -rf rsadec
	rm -rf privatekeytest
