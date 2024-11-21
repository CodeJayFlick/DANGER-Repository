Here is a translation of the Java code into equivalent Python:

```Python
import pymongo

class QuarkusMongoDatabaseClient:
    def __init__(self, database_name):
        self.mongo_clients = MongoClient()
        client = self.mongo_clients[database_name]
        configure(client)
        initialize()

# Define some utility functions
def configure(mongo_client):
    # Implement the configuration logic here
    pass

def initialize():
    # Implement the initialization logic here
    pass

if __name__ == "__main__":
    QuarkusMongoDatabaseClient("my_database")
```

Please note that this is a rough translation and might not work as-is. You would need to implement the `configure` and `initialize` functions according to your specific requirements.

Also, Python's syntax for creating objects and calling methods are different from Java. In Python, you don't have classes with constructors like in Java. Instead, you define class definitions using the `class` keyword, and then create instances of those classes by calling their constructor (which is actually a special method called `__init__`).