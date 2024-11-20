Here is the translation of the given Java code into Python:

```Python
import hamcrest as hc
from unittest import TestCase
from uuid import UUID

class SimpleObjectGlue(TestCase):

    def test_there_are_num_simple_objects(self):
        simple_objects = SimpleObjects()
        self.assertEqual(len(simple_objects.list_all()), 0)  # assuming list_all() returns an empty list initially
        
        for _ in range(5):  # replace with the actual number
            simple_objects.create(UUID.randomUUID().hex)
        
        self.assertEqual(len(simple_objects.list_all()), 5)

    def test_create_new_simple_object(self):
        simple_objects = SimpleObjects()
        new_id = UUID.randomUUID().hex
        simple_objects.create(new_id)
```

Please note that Python does not have direct equivalent of Java's `@Given` and `@When`. Instead, we use the built-in testing framework in Python. The test cases are defined using a class that inherits from TestCase.

Also, I've made some assumptions about how you would like to implement certain parts of your code (like replacing the actual number with 5). You might need to adjust these based on your specific requirements.