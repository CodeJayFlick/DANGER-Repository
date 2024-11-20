Here is the translation of the Java code to Python:
```
class YAFFS2Constants:
    MAGIC_SIZE = 11
    FILE_NAME_SIZE = 256
    ALIAS_FILE_NAME_SIZE = 160
    RECORD_SIZE = 2112
    HEADER_SIZE = 512
    EXTENDED_TAGS_SIZE = 64
    DATA_BUFFER_SIZE = 2048
    EMPTY_DATA_SIZE = 1536

YAFFS2Constants = YAFFS2Constants()
```
Note that in Python, we don't need to use the `public` keyword as it is not applicable. Also, I've kept the class name and variable names same as they were in Java, but you can rename them if needed.

Also, note that in Python, there's no concept of a "final" static integer like in Java. The values are simply assigned to variables.