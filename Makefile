all:
	gcc -gstabs+ -O0 enctest.c -o enctest

clean:
	rm -rf enctest
