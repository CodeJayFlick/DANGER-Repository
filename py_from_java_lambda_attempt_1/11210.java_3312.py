Here is the translation of the given Java interface into Python:

```Python
class Transaction:
    NOT_DONE = 0
    COMMITTED = 1
    ABORTED = 2
    NOT_DONE_BUT_ABORTED = 3

    def get_id(self):
        pass  # method to be implemented by subclass

    @property
    def description(self):
        pass  # property getter, method to be implemented by subclass

    @property
    def open_sub_transactions(self):
        return []  # list of strings representing sub-transactions

    def get_status(self):
        pass  # method to be implemented by subclass

    def has_committed_db_transaction(self):
        pass  # method to be implemented by subclass
```

Note that in Python, we don't have an equivalent concept like Java's `interface`. Instead, we define a class with abstract methods (methods without implementation) and properties. The subclasses of this class will need to implement these abstract methods and properties.

The `@property` decorator is used to create getter methods for the `description`, `open_sub_transactions`, and other attributes that are intended to be read-only or have custom behavior when accessed as attributes.