class FloatKind:
    FINITE = "FINITE"  # includes both normal and subnormal 
    INFINITE = "INFINITE"
    QUIET_NAN = "QUIET_NAN"
    SIGNALING_NAN = "SIGNALING_NAN"

# Note: In Python, enums are not built-in like in Java. Instead, we use class with constants.
