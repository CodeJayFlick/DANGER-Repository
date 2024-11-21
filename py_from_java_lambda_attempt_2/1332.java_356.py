Here is the translation of the given Java code into equivalent Python:

```Python
class GdbAddInferiorCommand:
    def __init__(self, manager):
        self.manager = manager

    def encode(self):
        return "-add-inferior"

    def complete(self, pending):
        if isinstance(pending, dict) and 'done' in pending:
            done_event = pending['done']
            iid = done_event.get('inferior_id', None)
            if iid is not None:
                return self.manager.getInferior(iid)

# Assuming GdbManagerImpl has a method getInferior
class GdbManagerImpl:
    def __init__(self):
        pass

    def getInferior(self, id):
        # Your implementation here
        pass


if __name__ == "__main__":
    manager = GdbManagerImpl()
    command = GdbAddInferiorCommand(manager)
```

Please note that Python does not have direct equivalent of Java's package structure. The above code is a simple translation and may need to be adjusted based on the actual implementation details in your project.