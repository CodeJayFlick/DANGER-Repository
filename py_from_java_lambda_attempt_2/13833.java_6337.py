Here is the translation of the Java interface `DbManager` to a Python class:

```python
class DbManager:
    def connect(self):
        # implementation for connecting to DB goes here
        pass

    def disconnect(self):
        # implementation for disconnecting from DB goes here
        pass

    def read_from_db(self, user_id: str) -> 'UserAccount':
        # implementation for reading data from DB goes here
        return None  # or some default UserAccount object if not found in the database

    def write_to_db(self, user_account: 'UserAccount') -> 'UserAccount':
        # implementation for writing data to DB goes here
        return user_account  # assuming it's a successful write operation

    def update_db(self, user_account: 'UserAccount') -> 'UserAccount':
        # implementation for updating record in DB goes here
        return user_account  # assuming the update is successful

    def upsert_db(self, user_account: 'UserAccount') -> 'UserAccount':
        # implementation for inserting or updating a record in DB goes here
        return user_account  # assuming it's either an insert or update operation
```

Note that I've used Python type hints to indicate the expected types of method parameters and return values. In particular, I've used the `->` syntax to specify the return type for each method.