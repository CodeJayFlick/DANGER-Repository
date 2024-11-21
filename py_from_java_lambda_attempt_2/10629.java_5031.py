Here is the translation of the given Java code into Python:

```Python
import unittest
from typing import List

class ReducingLCS:
    def __init__(self, x: str, y: str):
        self.x = x
        self.y = y

    def reduce(self, input: str, start: int, end: int) -> str:
        return input[start:end]

    def length_of(self, s: str) -> int:
        return len(s)

    def value_of(self, s: str, offset: int) -> str:
        return s[offset]


class TestReducingLCS(unittest.TestCase):

    @unittest.skip
    def test_identical(self):
        self.compare_strings("DEADBEEF", "DEADBEEF", "DEADBEEF")

    @unittest.skip
    def test_similar(self):
        self.compare_strings(
            "Some really long string that might complicate things." + 
                "Hooray for really long strings that span multiple lines!",
            "Some other really long string that might complicate things." +
                "Hooray for really loooooong strings that span multiple lines in java!",
            "Some really long string that might complicate things." +
                "Hooray for really long strings that span multiple lines!"
        )

    @unittest.skip
    def test_different(self):
        self.compare_strings("DEAD", "CANND", "AD")
        self.compare_strings("DEADBEEFISGOOD", "CANNDBEEFISBAD", "ADBEEFISD")
        self.compare_strings(
            "this here is one string",
            "here a different string is",
            "here in string"
        )

    @unittest.skip
    def test_insert_only(self):
        x = "Line not modified"
        y = "Line not not modified"
        self.compare_strings(x, y, x)

    @unittest.skip
    def test_removal_only(self):
        x = "Line not modified"
        y = "Line modified"
        self.compare_strings(x, y, y)

    @unittest.skip
    def test_size_limit(self):
        x = "This is a line that has not been modified"
        y = "This is a line that has been modified"

        slcs = ReducingLCS(x, y)
        slcs.set_size_limit(10)
        lcs = slcs.get_lcs()
        result = "".join(lcs)
        self.assertEqual(y, result)  # 'y' is common, since it is 'x', with only a delete

        z = "Start Mod " + x + " End Mod"  # same as 'x', but with different start/end
        slcs = ReducingLCS(x, z)
        slcs.set_size_limit(10)
        actual = slcs.get_lcs()
        self.assertTrue(actual == [])

    def compare_strings(self, x: str, y: str, expected: str):
        slcs = ReducingLCS(x, y)
        lcs = slcs.get_lcs()
        self.assertEqual(convert_string(expected), lcs)

    def convert_string(self, s: str) -> List[str]:
        char_list = []
        for c in s:
            char_list.append(c)
        return char_list


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. The test cases are defined as methods within the class, and they can be run using a testing framework like `unittest`.