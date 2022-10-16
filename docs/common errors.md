#### Dont use stack-based strings 
Wrap any string in \_s macro to create stack-based strings with no xref to strings' segment.

How to fix:
```
printf("Hello, world!");
```
to
```
printf(_s("Hello, world!"));
```
