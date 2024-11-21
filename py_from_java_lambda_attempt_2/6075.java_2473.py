Here is the equivalent Python code:

```Python
import unittest

class QueryOpinionServiceTest(unittest.TestCase):

    def test_secondary_attribute_matches(self):
        query_opinion_service = QueryOpinionService()

        flags1 = "111"
        attribute = "0b 00.. ..00 .... .... 00.10 0.0. 0000 ...."
        self.assertFalse(query_opinion_service.secondary_attribute_matches(flags1, attribute))

        flags2 = "821047567"
        self.assertTrue(query_opinion_service.secondary_attribute_matches(flags2, attribute))
        
        self.assertTrue(query_opinion_service.secondary_attribute_matches(flags2, attribute))

        flags3 = "269423616"
        self.assertTrue(query_opinion_service.secondary_attribute_matches(flags3, attribute))

        flags4 = "10817797"
        self.assertTrue(query_opinion_service.secondary_attribute_matches(flags4, attribute))


if __name__ == '__main__':
    unittest.main()
```

Note: The `QueryOpinionService` class is not defined in the original code. In Python, we would typically define this as a separate class with its own methods and attributes. For simplicity, I have assumed that it already exists and has been imported correctly.

Also note that there are no assertions for failure cases (i.e., when `secondary_attribute_matches()` returns False). You may want to add these depending on your testing requirements.