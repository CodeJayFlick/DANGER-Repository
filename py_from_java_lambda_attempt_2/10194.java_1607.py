Here is the translation of the given Java code into Python:

```Python
crc32tab = [0,1996959894,-301047508,...]  # You can copy-paste this list from your original code.

def hash_one_byte(hashcode, val):
    return crc32tab[(hashcode ^ val) & 0xff] ^ (hashcode >> 8)
```

Please note that you will need to manually enter the `crc32tab` list in Python as it is not directly translatable from Java.