Here is the translation of the Java code into Python:

```Python
class DbgListMappingsCommand:
    def __init__(self, manager, process):
        self.manager = manager
        self.process = process
        self.updated_thread_ids = []

    def complete(self, pending=None):
        threads = self.process.get_known_threads()
        current_threads = set(threads.keys())
        system_objects = self.manager.get_system_objects()
        previous_thread_id = system_objects.get_current_thread_id()

        for thread_id in self.updated_thread_ids:
            if thread_id in current_threads:
                continue  # Do nothing, we're in sync
            else:
                Msg.warn(self, f"Resync: Was missing thread {thread_id}")
                system_objects.set_current_thread_id(thread_id)
                tid = system_objects.get_current_thread_system_id()
                self.manager.thread_compute_if_absent(thread_id, self.process, tid)

        for thread_id in list(current_threads):
            if thread_id not in self.updated_thread_ids:
                continue  # Do nothing, we're in sync
            else:
                Msg.warn(self, f"Resync: Had extra thread {thread_id}")
                self.process.remove_thread(thread_id)
                self.manager.remove_thread(thread_id)

        system_objects.set_current_thread_id(previous_thread_id)
        return self.process.get_known_mappings()

    def invoke(self):
        # TODO
        pass

class DbgProcessImpl:
    def get_known_threads(self):
        # TO DO: implement this method
        pass

class DebugSystemObjects:
    def __init__(self, current_thread_id=None):
        self.current_thread_id = current_thread_id

    def set_current_thread_id(self, thread_id):
        self.current_thread_id = thread_id

    def get_current_thread_id(self):
        return self.current_thread_id
```

Please note that this is a direct translation of the Java code into Python. However, some methods like `get_known_threads`, `thread_compute_if_absent` and their counterparts in other classes are not implemented as they were not provided in the original Java code.