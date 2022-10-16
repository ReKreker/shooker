# Example
\> ```cd example/``` <br />
\> ```make compile``` <br />
gcc -c -o target.o target.c <br />
gcc -shared target.o -o libtarget.so <br />
gcc -O0 -L. -Wall -o leet_add leet_add.c -ltarget <br />
rm *.o <br />
\> ```make run``` <br />
LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./ ./leet_add <br />
3713 <br />
\> ```make hook``` <br />
./../src/shooker/__main__.py ./ ./ <br />
INFO: Patching libtarget.so... <br />
INFO: Compiling hook for add_n_print <br />
INFO: Patching the hook(s)... <br />
INFO: Hooking add_n_print <br />
INFO: Lib(s) patched <br />
\> ```make run``` <br />
LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./ ./leet_add <br />
Leet is 1337 <br />
