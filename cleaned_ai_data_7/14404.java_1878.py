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
