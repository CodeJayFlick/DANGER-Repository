class XCoffSymbolStorageClass:
    # beginning of the common block
    C_BCOMM = 135
    
    # beginning of include file
    C_BINCL = 108
    
    # beginning or end of inner block
    C_BLOCK = 100
    
    # beginning of static block
    C_BSTAT = 143
    
    # declaration of object (type)
    C_DECL = 140
    
    # local member of common block
    C_ECOMM = 136
    
    # end of include file
    C_EINCL = 109
    
    # alternate entry
    C_ENTRY = 141
    
    # end of static block
    C_ESTAT = 144
    
    # external symbol
    C_EXT = 2
    
    # beginning or end of function
    C_FCN = 101
    
    # source file name and compiler information
    C_FILE = 103
    
    # function or procedure
    C_FUN = 142
    
    # global variable
    C_GSYM = 128
    
    # unnamed external symbol
    C_HIDEXT = 107
    
    # comment section reference
    C_INFO = 100
    
    # automatic variable allocated on stack
    C_LSYM = 129
    
    # symbol table entry marked for deletion
    C_NULL = 0
    
    # argument to subroutine allocated on stack
    C_PSYM = 130
    
    # argument to function or procedure stored in register
    C_RPSYM = 132
    
    # register variable
    C_RSYM = 131
    
    # static symbol (unknown)
    C_STAT = 3
    
    # statically allocated symbol
    C_STSYM = 133
    
    # reserved
    C_TCSYM = 134
    
    # weak external symbol
    C_WEAKEXT = 111

XCoffSymbolStorageClass()
