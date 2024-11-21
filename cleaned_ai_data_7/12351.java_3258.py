class PackingType:
    """specifies the pack setting which applies to a composite data type.
       This can be DISABLED, DEFAULT, EXPLICIT."""
    
    class Disable: pass  # constant for disabled packing
    
    class Default: pass   # constant for default packing
    
    class Explicit: pass  # constant for explicit packing

# usage example:
print(PackingType.Disable)  # prints the disable constant
