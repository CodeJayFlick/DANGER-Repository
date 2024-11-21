Here is the equivalent Python code:

```
class LzssConstants:
    SIGNATURE_COMPRESSION = 0x636f6d70
    SIGNATURE_COMPRESSION_BYTES = bytes('comP', 'utf-8')

    SIGNATURE_LZSS = 0x6c7a7373
    SIGNATURE_LZSS_BYTES = bytes('lzsS', 'utf-8')

    PADDING_LENGTH = 22

    HEADER_LENGTH = (4 + 4 + 4 + 4) + PADDING_LENGTH
```