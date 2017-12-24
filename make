#!/bin/bash -x

#gcc -Wall -g -o test test.c -fPIE &&
#gcc -Wall -g -o libtrace.so -shared -fPIC trace.c  -ludis86 &&
gcc -Wall -Werror -g -o ftrace ftrace.c -lelf -ludis86 
#LD_PRELOAD=./libtrace.so ./test
