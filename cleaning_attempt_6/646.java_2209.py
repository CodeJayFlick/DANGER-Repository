class DbgSetActiveSessionCommand:
    def __init__(self, manager, session):
        self.manager = manager
        self.session = session

    def invoke(self):
        if self.session is not None:
            id = self.session.get_id()
            if id is not None:
                self.manager.get_system_objects().set_current_system_id(id)
