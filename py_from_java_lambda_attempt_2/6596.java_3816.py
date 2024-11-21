Here is the translation of the Java code into Python:

```Python
class AbstractProgramDiffTest:
    def __init__(self):
        self.program_diff = None
        self.program_builder1 = None
        self.program_builder2 = None
        self.p1 = None
        self.p2 = None

    def addr(self, offset):
        return self.p1.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def addr(self, program, offset):
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def addr(self, program, address_string):
        return program.getAddressFactory().getAddress(address_string)

    def check_no_comment_difference(self):
        self.program_diff = ProgramDiff(self.p1, self.p2)
        self.program_diff.set_filter(ProgramDiffFilter.COMMENT_DIFFS)
        diff_as = self.program_diff.get_differences(self.program_diff.get_filter(), None)
        assert_equal(diff_as, AddressSet())

    def check_diff(self, expected_diffs, diff_type):
        self.program_diff = ProgramDiff(self.p1, self.p2)
        self.program_diff.set_filter(diff_type)
        assert_equal(expected_diffs, self.program_diff.get_differences(self.program_diff.get_filter(), None))

    def create_data_reference(self, program, from_addr, to_addr):
        ref_mgr = program.getReferenceManager()
        ref_mgr.add_memory_reference(from_addr, to_addr, RefType.DATA, SourceType.USER_DEFINED, 0)

    def get_function(self, program, address_string):
        addr = self.addr(program, address_string)
        return program.getFunctionManager().get_function_at(addr)


# This is not part of the original Java code but it seems like a test class
class Test(AbstractProgramDiffTest):

    def setUp(self):
        super(Test, self).__init__()
        # Initialize your objects here

    def tearDown(self):
        pass  # You might need to clean up after each test


if __name__ == "__main__":
    t = Test()
    t.setUp()

    try:
        t.check_no_comment_difference()  # Your tests go here
    finally:
        t.tearDown()
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the code is translated to Python and might require some adjustments according to your specific use case.