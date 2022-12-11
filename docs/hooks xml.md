# shook
Structure map:<br />
[shook](#shook)<br />
| [default\_cc](#default_cc)<br />
| | [compiler](#default-compiler)<br />
| | [arch & mode](#default-arch--mode)<br />
| [lib\_hook](#lib_hook)<br />
| | [compiler](#compiler)<br />
| | [arch & mode](#arch--mode)<br />
| | [include](#include)<br />
| | | [func](#func)<br />
| | | [lib](#lib)<br />
| | [hook](#hook)<br />

---
## default\_cc
### default compiler
Path to default compiler that will be used for compiling patch(s). Use only gnu gcc because in the project was used Labels as Values asm-trick that supported only by gnu gcc.
### default arch & mode
Default architecture and mode for disassembling by Capstone:
- CS\_ARCH\_ARM
    - CS\_MODE\_ARM
    - CS\_MODE\_THUMB
- CS\_ARCH\_ARM64
    - CS\_MODE\_ARM
- CS\_ARCH\_MIPS
    - CS\_MODE\_MIPS32
    - CS\_MODE\_MIPS64
    - CS\_MODE\_MIPS32R6
- CS\_ARCH\_PPC
    - CS\_MODE\_32
    - CS\_MODE\_64
- CS\_ARCH\_SPARC
- CS\_ARCH\_SYSZ
- CS\_ARCH\_X86
    - CS\_MODE\_16
    - CS\_MODE\_32
    - CS\_MODE\_64
- CS\_MODE\_XCORE
## lib\_hook
An entry that describes how to hook a specific library
### compiler
The same as default compiler but more this preferred for current library
### arch & mode
The same as default arch & mode but more this preferred for current library
### include
Define which funcs and libs must be imported for patchs. Imported functions can be used in any \<patch\> for current library to hook.
#### func
- import: it will searching function address from import table
- local: it will searching function from library for hook
#### lib
- system: #include \<system\_lib.h\> 
- local: #include "our\_lib.h"<br />
**Only libs with fully-inline functions can be included!**
### hook
Define hooked function and hook's code. Have to use _s() for create stack-based strings to avoid broken xref. 

```
<?xml version="1.0" encoding="UTF-8"?>
<shook>
    <default_cc>
        <compiler>/usr/bin/gcc</compiler>
        <arch>CS_ARCH_X86</arch>
        <mode>CS_MODE_64</mode>
    </default_cc>
    <lib_hook path="libarmtarget.so">
        <compiler>/usr/bin/aarch64-linux-gnu-gcc</compiler>
        <arch>CS_ARCH_ARM</arch>
        <mode>CS_MODE_ARM</mode>
        <include>
            <func proto="int FUNC(char *, ...)" kind="import">printf</func>  <!-- get import from injected lib -->
            <func proto="void FUNC(char *)" kind="local">do_kek</func>      <!-- get local function from injected lib -->
        </include>
        <hook proto="void FUNC(int arg1, int arg2)" name="func1">
            printf(_s("%d\n"), arg1*100+arg2/100);
        </hook>
        <hook proto="void FUNC(char *str)" name="func2">
            do_kek(str);
            printf(_s("Keked\n"));
        </hook>
    </lib_hook>
    <lib_hook path="lib86target.so">
        <mode>CS_MODE_32</mode> <!-- default /usr/bin/gcc & CS_ARCH_X86 -->
        <include>
            <lib kind="system">some_lib_a.h</lib>  <!-- transform to #include <some_lib_a.h> -->
            <lib kind="local">some_lib_b.h</lib>   <!-- transform to #include "some_lib_b.h" -->
        </include>
        <hook proto="int FUNC(int arg1)" name="func3">
            return arg1 + 10; 
        </hook>
        <hook proto="void FUNC(char *str)" name="func4">
            do_print(str);
        </hook>
    </lib_hook>
</shook>
```
