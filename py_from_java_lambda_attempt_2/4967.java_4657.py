Here is the translation of the Java code to Python:

```Python
class PdbParserConstants:
    """Program Information options related to PDB data."""
    
    # Option key which indicates if PDB has been loaded/applied to program (Boolean).
    PDB_LOADED = "PDB Loaded"
    
    # Option key which indicates PDB filename or path as specified by loaded program (String).
    PDB_FILE = "PDB File"
    
    # Option key which indicates PDB Age as specified by loaded program (String, hex value without 0x prefix).
    PDB_AGE = "PDB Age"
    
    # Option key which indicates PDB Signature as specified by loaded program (String).
    PDB_SIGNATURE = "PDB Signature"
    
    # Option key which indicates PDB Version as specified by loaded program (String).
    PDB_VERSION = "PDB Version"
    
    # Option key which indicates PDB GUID as specified by loaded program (String).
    PDB_GUID = "PDB GUID"

# Example usage:
program_info_options = {"PDB Loaded": False, "PDB File": "", "PDB Age": "", "PDB Signature": "", "PDB Version": "", "PDB GUID": ""}
```

Note that Python does not have a direct equivalent to Java's `public final static` keywords. In Python, we can achieve similar functionality using class variables and string constants.