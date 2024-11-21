Here's a translation of the Java code into equivalent Python:

```Python
class OatDexFileOreo:
    def __init__(self, reader, vdex_header):
        super().__init__(reader)
        self.vdex_header = vdex_header
        if vdex_header is not None:
            for i in range(len(vdex_header.dex_checksums)):
                if vdex_header.dex_checksums[i] == self.get_dex_file_checksum():
                    self.dex_header = vdex_header.dex_header_list[i]
                    break

    def get_vdex_header(self):
        return self.vdex_header

    def is_dex_header_external(self):
        return True
```

Please note that Python does not have direct equivalent of Java's package, class and method declarations. Also, the `@Override` annotation in Java has no direct equivalent in Python as it is used to indicate that a method is overriding one from its superclass.