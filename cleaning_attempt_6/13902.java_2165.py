class Database:
    def __init__(self):
        pass

    def add(self, obj) -> T:
        raise NotImplementedError("Method 'add' must be implemented by subclass")

    def get(self, id: str) -> T:
        raise NotImplementedError("Method 'get' must be implemented by subclass")
