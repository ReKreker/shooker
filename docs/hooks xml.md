# shook
## compiler
Path to compiler that will be used for compiling patch(s). Use only gnu gcc because in the project was used Labels as Values asm-trick that supported only by gnu gcc.
## lib_hook
An entry that describes how to hook a specific library
### arch & mode
Architecture and mode for disassembling by Capstone:
- CS_ARCH_ARM
    - CS_MODE_ARM
    - CS_MODE_THUMB
- CS_ARCH_ARM64
    - CS_MODE_ARM
- CS_ARCH_MIPS
    - CS_MODE_MIPS32
    - CS_MODE_MIPS64
    - CS_MODE_MIPS32R6
- CS_ARCH_PPC
    - CS_MODE_32
    - CS_MODE_64
- CS_ARCH_SPARC
- CS_ARCH_SYSZ
- CS_ARCH_X86
    - CS_MODE_16
    - CS_MODE_32
    - CS_MODE_64
- CS_MODE_XCORE
### include
Define which funcs and libs must be imported for patchs. Imported functions can be used in any \<patch\> for current library to hook.
#### func
- import: it will searching function address from import table
- symbol: it will searching function from symbols of library for hook
#### lib
- system: #include \<system_lib.h\> 
- local: #include "our_lib.h"<br />
**Only libs with fully-inline functions can be included!**
### hook
Define hooked function and hook's code. Have to use _s() for create stack-based strings to avoid broken xref. 

```
<?xml version="1.0" encoding="UTF-8"?>
<shook>
    <compiler>/usr/bin/gcc</compiler>
    <lib_hook path="libtarget.so">
        <arch>CS_ARCH_X86</arch>
        <mode>CS_MODE_64</mode>
        <include>
            <func proto="int FUNC(char *, ...)" kind="import">printf</func>  <!-- get import from injected lib -->
            <func proto="void FUNC(char *)" kind="symbol">do_kek</func>      <!-- get symbol from injected lib -->
            <!-- <lib kind="system">some_lib.h</lib> -->                     <!-- transform to #include <some_lib.h> -->
            <!-- <lib kind="local">some_lib.h</lib> -->                      <!-- transform to #include "some_lib.h" -->
        </include>
        <hook proto="void FUNC(int arg1, int arg2)" name="func1">
            printf(_s("%d\n"), arg1*100+arg2/100);
        </hook>
        <hook proto="void FUNC(char *str)" name="func2">
            do_kek(str);
            printf(_s("Keked\n"));
        </hook>
    </lib_hook>
</shook>
```