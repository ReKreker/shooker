#### Multiple calls the same func at one line
```│translation.c:7:51: error: duplicate label ‘func_name_jmp_10’```

How to fix:
```printf(_s("Leet is %d\n"), arg1*100+arg2/100); printf(_s("Trigger error"));```
to
```
printf(_s("Leet is %d\n"), arg1*100+arg2/100);
printf(_s("Test"));
```
