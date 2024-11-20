Here is the equivalent Python code:

```Python
def htonl(value):
    return [(value >> i) & 0xFF for i in range(24, -1, -8)]
```

This function takes an integer `value` as input and returns a list of bytes representing the value in network byte order. The expression `(value >> i) & 0xFF` extracts the i-th byte from the value (with `i=0` being the least significant byte).