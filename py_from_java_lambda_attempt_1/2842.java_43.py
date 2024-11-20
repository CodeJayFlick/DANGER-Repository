Here is the translation of the given Java code into equivalent Python:

```Python
class UndoableTransaction:
    @staticmethod
    def start(domain_object=None, description="", commit_by_default=True):
        if domain_object:
            return DomainObjectUndoableTransaction(domain_object, 0, commit_by_default)
        elif isinstance(description, str) and not domain_object:
            raise ValueError("Either a domain object or a string description must be provided")
        else:
            return ProgramUserDataUndoableTransaction(None, 0)

    @staticmethod
    def start(data_type_manager=None, description="", commit_by_default=True):
        if data_type_manager:
            return DataTypeManagerUndoableTransaction(data_type_manager, 0, commit_by_default)
        elif isinstance(description, str) and not data_type_manager:
            raise ValueError("Either a data type manager or a string description must be provided")
        else:
            return ProgramUserDataUndoableTransaction(None, 0)

    @staticmethod
    def start(userData=None):
        if userData:
            return ProgramUserDataUndoableTransaction(userData, 0)
        else:
            return None

class AbstractUndoableTransaction:
    def __init__(self, transaction_id, commit_by_default=True):
        self.transaction_id = transaction_id
        self.commit = commit_by_default
        self.open = True

    def end_transaction(self, commit=False):
        pass

    def abort(self):
        if self.open:
            self.open = False
            self.end_transaction(False)

    def close(self):
        if self.open:
            self.end_transaction(self.commit)
        else:
            raise ValueError("Transaction is already closed")

class DomainObjectUndoableTransaction(AbstractUndoableTransaction):
    def __init__(self, domain_object, transaction_id, commit_by_default=True):
        super().__init__(transaction_id, commit_by_default)
        self.domain_object = domain_object

    def end_transaction(self, commit=False):
        if not commit:
            print("Aborting transaction")
        self.domain_object.end_transaction(self.transaction_id, commit)

class DataTypeManagerUndoableTransaction(AbstractUndoableTransaction):
    def __init__(self, data_type_manager, transaction_id, commit_by_default=True):
        super().__init__(transaction_id, commit_by_default)
        self.data_type_manager = data_type_manager

    def end_transaction(self, commit=False):
        self.data_type_manager.end_transaction(self.transaction_id, commit)

class ProgramUserDataUndoableTransaction(AbstractUndoableTransaction):
    def __init__(self, userData, transaction_id):
        super().__init__(transaction_id, True)
        self.userData = userData

    def abort(self):
        raise ValueError("Aborting a program user data undoable transaction is not supported")

# Example usage:
domain_object_undoable_transaction = UndoableTransaction.start(domain_object=None, description="", commit_by_default=True)

data_type_manager_undoable_transaction = UndoableTransaction.start(data_type_manager=None, description="", commit_by_default=True)
```

Please note that Python does not have direct equivalent of Java's `AutoCloseable` interface. Also, the code provided doesn't include any exception handling which is a common practice in both languages.