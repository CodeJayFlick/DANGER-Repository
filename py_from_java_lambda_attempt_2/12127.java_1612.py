Here is the translation of the given Java code into Python:

```Python
class Query:
    """Query interface used to test a record for some condition."""
    
    def matches(self, record):
        """
        Returns True if the given record matches the query's condition.
        
        :param record: The record to test for compliance.
        :return: A boolean indicating whether the record matches the query's condition.
        """
        pass  # This method should be implemented by a subclass
```

Note that in Python, we don't have an equivalent of Java interfaces. Instead, we can use abstract base classes (ABCs) or protocols to define a common interface for subclasses. In this case, I've used the `class` keyword to define a class with one method (`matches`) which should be implemented by any subclass that wants to conform to this "interface".