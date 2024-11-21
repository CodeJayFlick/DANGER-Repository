Here is the translation of the given Java code into Python:

```Python
class DbgSessionImpl:
    def __init__(self, manager=None, id=None):
        self.manager = manager
        self.id = id
        self.processes = {}
        self.unmodifiable_processes = {k: v for k, v in self.processes.items()}
        self.exit_code = None

    def __str__(self):
        return f"<DbgSession id={self.id}, exitCode={self.exit_code}>"

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def exit_code(self):
        return self._exit_code

    @exit_code.setter
    def exit_code(self, value):
        self._exit_code = value

    def add(self):
        if not hasattr(self.manager, 'sessions'):
            raise AttributeError("Manager does not have a sessions attribute")
        self.manager.sessions[self.id] = self
        #self.manager.add_session(self)

    def remove(self, cause=None):
        if not hasattr(self.manager, 'remove_session'):
            raise AttributeError("Manager does not have a remove_session method")
        self.manager.remove_session(self.id, cause)

    def add_process(self, process):
        if process.id in self.processes:
            raise ValueError(f"There is already a process with id {process.id}")
        self.processes[process.id] = process

    def get_process(self, tid):
        return self.processes.get(tid)
    
    def remove_process(self, pid):
        if pid not in self.processes:
            raise ValueError(f"There is no process with id {pid}")
        del self.processes[pid]

    @property
    def known_processes(self):
        return self.unmodifiable_processes

    @property
    def known_process_impl(self):
        return self.processes

    async def list_processes(self):
        if not hasattr(self.manager, 'execute'):
            raise AttributeError("Manager does not have an execute method")
        command = DbgListProcessesCommand(self.manager)
        return await self.manager.execute(command)

    def process_created(self, process):
        self.processes[process.id] = process

    def process_exited(self, id):
        if id in self.processes:
            del self.processes[id]
```

Note that the `CompletableFuture` class from Java does not have a direct equivalent in Python. The `list_processes` method has been modified to return an asynchronous result using the `async/await` syntax.