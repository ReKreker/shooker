#!/usr/bin/bash
if [[  $@ == "--help" ||  $@ == "-h" || "$1" == "" || "$2" == "" ]]
then 
    echo -e "Usage: \n\t$(basename $0) TEST_NUMBER TEST_NAME"
	exit 0
fi 
NUMBER=$(printf "%03d" $1)
NAME=$2

TEST_PATH="${NUMBER}${NAME}"
mkdir $TEST_PATH

NAME=${NAME,} # to lowercase first letter
echo -e $(cat << EOF
#include "victum.h"\n
\n
int main() {\n
\tif (${NAME}Test(13))\n
\t\treturn 1;\n
\treturn 0;\n
}\n
EOF
) > $TEST_PATH/check.c

echo -e $(cat << EOF
int ${NAME}Test(int);\n
EOF
) > $TEST_PATH/victum.h

echo -e $(cat << EOF
#include "victum.h"\n
\n
int ${NAME}Test(int x) { ; }\n
EOF
) > $TEST_PATH/victum.c

echo -e $(cat << EOF
set(CMAKE_C_FLAGS "-fPIC")\n
add_library(${NUMBER}Lib SHARED victum.c)\n
\n
add_executable(${NUMBER}Bin check.c)\n
target_link_libraries(${NUMBER}Bin ${NUMBER}Lib)\n
EOF
) > $TEST_PATH/CMakeLists.txt

echo -e $(cat << EOF
<?xml version="1.0" encoding="UTF-8"?>\n
<shook>\n
\t<default_cc>\n
\t\t<compiler>/usr/bin/gcc</compiler>\n
\t\t<arch>CS_ARCH_X86</arch>\n
\t\t<mode>CS_MODE_64</mode>\n
\t</default_cc>\n
\t<lib_hook path="libarmtarget.so">\n
\t\t<include>\n
\t\t\t<func proto="int FUNC(char *, ...)" kind="import">printf</func>\n
\t\t\t<func proto="void FUNC(char *)" kind="local">do_kek</func>\n
\t\t\t<lib kind="system">some_lib_a.h</lib>\n
\t\t\t<lib kind="local">some_lib_b.h</lib>\n
\t\t</include>\n
\t\t<hook proto="void FUNC(int arg1, int arg2)" name="func1">\n
\t\t\tprintf(_s("%d\n"), arg1*100+arg2/100);\n
\t\t</hook>\n
\t</lib_hook>\n
</shook>\n
EOF
) > $TEST_PATH/hooks.xml
