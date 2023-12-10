#!/bin/bash

i686-w64-mingw32-gcc -c entry.cpp -o interactive_execute_shellcode.x86.o
x86_64-w64-mingw32-gcc -c entry.cpp -o interactive_execute_shellcode.x64.o