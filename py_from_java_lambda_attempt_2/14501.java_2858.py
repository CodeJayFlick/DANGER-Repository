Here is the translation of the given Java code into Python:

```Python
import unittest
from hamcrest import assert_that, instance_of, not_

class ThiefTest(unittest.TestCase):

    def test_thief(self):
        thief = Thief()
        assert_that(thief, not_(instance_of(Permission)))

if __name__ == '__main__':
    unittest.main()
```

Please note that the `Thief` class and `Permission` class are assumed to be defined elsewhere in your Python code.