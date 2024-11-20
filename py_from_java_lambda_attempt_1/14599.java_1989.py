Here is the translation of the Java code to Python:
```python
import unittest
from unittest.mock import patch, Mock
from collections import defaultdict

class SimpleObjectsTest(unittest.TestCase):
    def setUp(self):
        self.simple_objects = SimpleObjects()
        self.container = Mock()

    @patch('domainapp.dom.modules.simple.DomainObjectContainer')
    def test_create(self, mock_container):
        # given
        simple_object = SimpleObject()
        sequence = unittest.mock.patch.object(mock_container, 'new_transient_instance', return_value=simple_object)
        mock_container.persist_if_not_already.return_value = simple_object

        # when
        object_name = "Foobar"
        obj = self.simple_objects.create(object_name)

        # then
        self.assertEqual(simple_object, obj)
        self.assertEqual(obj.name, object_name)

    @patch('domainapp.dom.modules.simple.DomainObjectContainer')
    def test_list_all(self, mock_container):
        # given
        all_instances = [SimpleObject() for _ in range(5)]

        sequence = unittest.mock.patch.object(mock_container, 'all_instances', return_value=all_instances)
        self.assertEqual(all_instances, self.simple_objects.list_all())

if __name__ == '__main__':
    unittest.main()
```
Note that I used the `unittest` module to write unit tests, and the `mock` library from Python's standard library to mock out dependencies. The rest of the code is straightforward translations from Java to Python.

Also, please note that this translation assumes you have a `SimpleObjects` class with methods like `create()` and `list_all()`, as well as a `DomainObjectContainer` class (which I mocked in the tests).