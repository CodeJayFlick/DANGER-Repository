Here is the translation of the Java code to Python:
```
import io

class GenericDomainObjectDB:
    def __init__(self, consumer):
        self.current_transaction = None
        self.transactions_list = []

    def get_description(self):
        return "Generic Database Domain Object"

    def is_changeable(self):
        return False

    def start_transaction(self, description, listener):
        self.current_transaction = description
        return super().start_transaction(description, listener)

    def end_transaction(self, transaction_id, commit):
        super().end_transaction(transaction_id, commit)
        if not commit:
            self.transactions_list.append(self.current_transaction)
        self.current_transaction = None

class DomainObjectAdapterDB:
    pass  # This class is abstract in Java and doesn't have a direct equivalent in Python
```
Note that I've omitted the `IOException` import statement since it's not relevant to this code. Additionally, I've removed the `@Override` annotations as they are not necessary in Python.

Also, note that I've created an empty class `DomainObjectAdapterDB` which is abstract in Java and doesn't have a direct equivalent in Python. In Python, you can simply define a new method or attribute without declaring it as abstract.