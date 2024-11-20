Here is the translation of the given Java code into Python:

```Python
class SizeSelector:
    def __init__(self, size):
        self.size = size

    def test(self, creature: 'Creature') -> bool:
        return creature.get_size() == self.size


import unittest.mock as mock
from unittest import TestCase

class TestSizeSelector(TestCase):

    @mock.patch('creature.Creature')
    def test_movement(self, mock_creature):
        normal_creature = mock.Mock(spec=mock_creature)
        small_creature = mock.Mock(spec=mock_creature)

        normal_creature.size.return_value = 'NORMAL'
        small_creature.size.return_value = 'SMALL'

        selector = SizeSelector('NORMAL')
        self.assertTrue(selector.test(normal_creature))
        self.assertFalse(selector.test(small_creature))


if __name__ == '__main__':
    unittest.main()
```

Please note that this Python code uses the `unittest.mock` module for mocking, which is similar to Mockito in Java. Also, I have used type hints where possible and made some minor adjustments to fit the style of Python programming.