Here is the equivalent Python code:

```Python
import unittest

class PEUtilTest(unittest.TestCase):

    def test_is_visual_studio_or_clang_pe_given_visual_studio_pe(self):
        program = build_64_bit_x86()
        result = pe_util.is_visual_studio_or_clang_pe(program)
        self.assertTrue(result)

    def test_is_visual_studio_or_clang_pe_given_clang_pe(self):
        program = build_64_bit_x86_clang()
        result = pe_util.is_visual_studio_or_clang_pe(program)
        self.assertTrue(result)

    def test_is_visual_studio_or_clang_pe_given_not_visual_studio_or_clang_pe(self):
        program = build_64_bit_x86_non_vs()
        result = pe_util.is_visual_studio_or_clang_pe(program)
        self.assertFalse(result)


def build_64_bit_x86():
    # implement this function
    pass

def build_64_bit_x86_clang():
    # implement this function
    pass

def build_64_bit_x86_non_vs():
    # implement this function
    pass


pe_util = {
    'is_visual_studio_or_clang_pe': lambda program: True  # or False, depending on your implementation
}
```

Please note that the `build_64_bit_x86`, `build_64_bit_x86_clang` and `build_64_bit_x86_non_vs` functions are not implemented in this code. You would need to implement these functions based on how you're building your programs.