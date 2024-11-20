Here is the translation of the Java interface `TransactionListener` into a Python class:

```python
class TransactionListener:
    def transaction_started(self, domain_obj: 'DomainObjectAdapterDB', tx):
        pass  # Implement this method in your subclass

    def transaction_ended(self, domain_obj: 'DomainObjectAdapterDB'):
        pass  # Implement this method in your subclass

    def undo_stack_changed(self, domain_obj: 'DomainObjectAdapterDB'):
        pass  # Implement this method in your subclass

    def undo_redo_occurred(self, domain_obj: 'DomainObjectAdapterDB'):
        pass  # Implement this method in your subclass
```

Note that I've used type hints for the `domain_obj` parameter to indicate its expected type. In Python, these are not enforced at runtime like they would be in Java with an interface; instead, you can use tools like mypy or PyCharm's static analysis to check for type errors.

Also note that I haven't implemented any actual logic within the methods themselves - this is because the original code was just defining an interface (or abstract class) and not providing concrete implementations. In Python, we typically define classes with methods that can be overridden by subclasses or used as-is.