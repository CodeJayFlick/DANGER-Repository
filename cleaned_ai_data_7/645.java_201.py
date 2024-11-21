class DbgSetActiveProcessCommand:
    def __init__(self, manager: 'DbgManagerImpl', process: 'DbgProcess'):
        self.manager = manager
        self.process = process

    def invoke(self):
        if self.process is not None:
            id = self.process.get_id()
            if id is not None:
                so = self.manager.get_system_objects()
                current_process_id = so.get_current_process_id()
                if id.id != current_process_id.id:
                    so.set_current_process_id(id)
