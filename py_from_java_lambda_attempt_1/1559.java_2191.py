Here is the translation of the given Java code into equivalent Python:

```Python
class LldbListProcessesCommand:
    def __init__(self, manager, session):
        self.manager = manager
        self.session = session
        self.updated_processes = {}

    def complete(self, pending=None):
        all_processes = self.manager.get_known_processes(self.session)
        current_ids = set(all_processes.keys())
        
        for id in list(self.updated_processes.keys()):
            if id in current_ids:
                del self.updated_processes[id]
            else:
                self.manager.add_process_if_absent(self.session, self.updated_processes.pop(id))
                
        session_id = DebugClient.get_id(self.session)
        for id in list(current_ids):
            if id not in self.updated_processes:
                self.manager.remove_process(session_id, id, Causes.UNCLAIMED)

    def invoke(self):
        process = self.session.GetProcess()
        self.updated_processes[DebugClient.get_id(process)] = process
```

Note that Python does not have direct equivalents for Java's `Map`, `Set`, and other collections. Instead, we use built-in dictionaries (`{}`) to represent maps and sets are represented as a set data type in Python.

Also note that the equivalent of Java's `HashMap` is Python's dictionary `{}`, which provides similar functionality but with some differences (e.g., it does not have a direct equivalent for Java's `put()` method).