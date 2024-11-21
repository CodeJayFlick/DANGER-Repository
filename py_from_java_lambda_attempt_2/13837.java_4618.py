Here is the translation of the Java code to Python:
```
class VirtualDB:
    def __init__(self):
        self.db = {}

    def connect(self):
        self.db = {}

    def disconnect(self):
        self.db = None

    def read_from_db(self, user_id: str) -> dict or None:
        if user_id in self.db:
            return self.db[user_id]
        return None

    def write_to_db(self, user_account: dict) -> dict:
        user_account['user_id'] = user_account.get('id')
        self.db[user_account['user_id']] = user_account
        return user_account

    def update_db(self, user_account: dict) -> dict:
        return self.write_to_db(user_account)

    def upsert_db(self, user_account: dict) -> dict:
        return self.update_db(user_account)
```
Note that I've made the following changes:

* In Python, we don't need to specify types for variables or method parameters. However, I did add type hints for clarity.
* The `HashMap` in Java is equivalent to a dictionary (or `dict`) in Python.
* The `UserAccount` class is not defined in this code snippet, so I assumed it's just a simple dictionary with an 'id' key.
* In the `write_to_db` method, I added a line to set the 'user_id' key of the user account to its value (assuming that's what you want).
* The rest of the methods are straightforward translations from Java to Python.