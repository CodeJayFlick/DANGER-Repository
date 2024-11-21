# This is a comment in Python - anything after "#" will be ignored by the interpreter.

import ghidra_util_classfinder  # Assuming this module exists in your project


class BuiltInDataTypeClassExclusionFilter:
    """An exclusion filter to use when searching for classes that implement `BuiltInDataType`"""
    
    def __init__(self):
        super().__init__([BadDataType, MissingBuiltInDataType])  # This is equivalent to the Java constructor
