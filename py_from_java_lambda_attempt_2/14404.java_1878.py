Here is the translation of the Java code to Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import unittest
from typing import Any, Callable, List

class MinusExpressionTest(unittest.TestCase):
    def setUp(self):
        super().__init__()
        self.expression_provider = lambda f, s: f - s

    def test_expression_provider(self) -> List[dict]:
        return list(map(lambda x: {'f': x['f'], 's': x['s']}, [
            {'f': 1, 's': 2},
            # Add more test cases here
        ]))

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the JUnit framework. The code above is a simple translation of your original code and may need to be modified based on how you plan to use it in your actual project.

Also, note that I used the built-in unittest module from Python's standard library instead of JUnit Jupiter as there isn't an equivalent for Python.