Here is a translation of the Java class into equivalent Python code:

```Python
class SectionNames:
    TEXT = "__text"
    TEXT_CSTRING = "__cstring"
    TEXT_PICSYMBOL_STUB = "__picsymbol_stub"
    TEXT_SYMBOL_STUB = "__symbol_stub"
    TEXT_CONST = "__const"
    TEXT_LITERAL4 = "__literal4"
    TEXT_LITERAL8 = "__literal8"
    TEXT_FVMLIB_INIT0 = "__fvmlib_init0"
    TEXT_FVMLIB_INIT1 = "__fvmlib_init1"

    DATA = "__data"
    DATA_LA_SYMBOL_PTR = "__la_symbol_ptr"
    DATA_NL_SYMBOL_PTR = "__nl_symbol_ptr"
    DATA_DYLD = "__dyld"
    DATA_CONST = "__const"
    DATA_MOD_INIT_FUNC = "__mod_ init_func"
    DATA_MOD_TERM_FUNC = "__mod_term_func"
    SECT_BSS = "__bss"
    SECT_COMMON = "__common"

    GOT = "__got"
    OBJC_SYMBOLS = "__symbol_table"
    OBJC_MODULES = "__module_info"
    OBJC_STRINGS = "__selector_ strs"
    OBJC_REFS = "__selector_refs"

    IMPORT_JUMP_TABLE = "__jump_table"
    IMPORT_POINTERS = "__pointers"
    PROGRAM_VARS = "__program_vars"


# You can access the section names like this:
print(SectionNames.TEXT)
```

This Python code defines a class `SectionNames` with static attributes that correspond to the Java constants.