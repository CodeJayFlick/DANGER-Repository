class DbgRemoveSessionCommand:
    def __init__(self, manager: 'DbgManager', id: int):
        self.manager = manager
        self.id = id

    def invoke(self) -> None:
        session = self.manager.get_session(self.id)
        if session is not None:
            self.manager.remove_session(session)

class DbgManager:
    pass  # placeholder for the class, actual implementation depends on your use case

# Example usage:

manager = DbgManager()  # initialize the manager
id = 123  # some process ID
command = DbgRemoveSessionCommand(manager, id)
command.invoke()
