Here is the translation of the Java code into Python:

```Python
class X86_32_MachoRelocationConstants:
    """X86_32 Macho Relocation Constants"""

    GENERIC_RELOC_VANILLA = 0
    """Generic relocation"""
    
    GENERIC_RELOC_PAIR = 1
    """Only follows a GENERIC_RELOC_SECTDIFF"""
    
    GENERIC_RELOC_SECTDIFF = 2
    """The difference of two symbols defined in two different sections"""
    
    GENERIC_RELOC_PB_LA_PTR = 3
    """Pre-bound lazy pointer"""
    
    GENERIC_RELOC_LOCAL_SECTDIFF = 4
    """The difference of two symbols defined in two different sections"""
    
    GENERIC_RELOC_TLV = 5
    """Thread local variables"""

# Example usage:
print(X86_32_MachoRelocationConstants.GENERIC_RELOC_VANILLA)
```

Note that Python does not have a direct equivalent to Java's `public final static` keywords. In Python, these constants are simply defined as class attributes and can be accessed directly from the class name.