### Coding style

Two spaces for indentation
80 rowlength
new row after variables in functions
Counters : i, j, k, l...
for loops : for (int i = 0; i < 10; i++) {}
If possible keep things on as few lines as possible.
This:
```
for (int i = 0; i < 10; i++) {printf("%d\n", i);}
```
Rather than this:
```
for (int i = 0; i < 10; i++) {
  printf("%d\n", i);
}
```
Functions:
```
void lkeys_func(int a, int b) { // l for light
  int x;

  do_stuff(a);
  do_other(b);
  stuff(0);
}
```
