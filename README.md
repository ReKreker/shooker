# Shooker
Tool for C-code injections in already compiled bins.

## Usage
Write hook config as described in the [instruction](https://github.com/ReKreker/shooker/blob/master/docs/hooks%20xml.md).

```shooker --xml config.xml target_dir/ output_dir/```

## Install
```pip install shooker```<br />
*Please read about [common errors](https://github.com/ReKreker/shooker/blob/master/docs/common%20errors.md)*

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
INFO: Patching libtarget.so... <br />
INFO: Compiling hook for add_n_print <br />
INFO: Patching the hook(s)... <br />
INFO: Hooking add_n_print <br />
INFO: Lib(s) patched <br />
\> ```make run``` <br />
LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:./ ./leet_add <br />
Leet is 1337 <br />

## To improve
- Add ability to inject to .exe/.dll
- Try to avoid sub-instruction patching mechanism in the hook(s)
- Add support of arm architecture
- Add support hooking raw binaries
- Develop true hook(not replace)
