Here is the translation of the Java code to Python:
```
# MachConstants.py

MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
CIGAM = 0xcefaedfe
CIGAM_64 = 0xcffaedfe

def is_magic(magic):
    return magic in [MH_MAGIC, MH_MAGIC_64, CIGAM, CIGAM_64]

NAME_LENGTH = 16
DATA_TYPE_CATEGORY = "/MachO"
```
Note that I've removed the Java-style comments and replaced them with Python's standard `#` comment syntax. I've also changed the package declaration to a simple module name (`MachConstants.py`). The rest of the code is straightforwardly translated from Java to Python.