# Shooker
Tool for C-code injections in already compiled bins.

## Usage
Write hook config as described in the [instruction](docs/hooks%20xml.md).

```shooker --xml config.xml target_dir/ output_dir/```

## Example
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
./../shooker ./ ./ <br />
Patching libtarget.so... <br />
Compiling hook for add_n_print <br />
Patching the hook(s)... <br />
Hooking add_n_print <br />
Lib(s) patched <br />
\> ```make run``` <br />
LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./ ./leet_add <br />
1337 <br />

## Install
```pip install shooker```

## To improve
- Add ability to inject to .exe/.dll
- Try to avoid sub-instruction patching mechanism in the hook(s)
- Add support of arm architecture
- Add support hooking raw binaries