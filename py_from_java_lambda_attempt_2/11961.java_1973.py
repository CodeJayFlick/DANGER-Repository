Here is the translation of the Java code into Python:

```Python
class ListingDB:
    def __init__(self):
        self.program = None
        self.code_mgr = None
        self.tree_mgr = None
        self.function_mgr = None

    # ... other methods ...

    def set_program(self, program):
        self.program = program
        self.code_mgr = program.get_code_manager()
        self.tree_mgr = program.get_tree_manager()
        self.function_mgr = program.get_function_manager()

    def getCodeUnitAt(self, addr):
        return self.code_mgr.getCodeUnitAt(addr)

    # ... other methods ...

    def getFunctionContaining(self, addr):
        return self.function_mgr.getFunctionContaining(addr)
```

Note that this is a simplified translation and may not cover all the cases. The original Java code has many more methods and conditions which are not included here for simplicity.