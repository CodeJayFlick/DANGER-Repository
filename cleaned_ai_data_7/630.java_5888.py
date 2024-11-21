class DbgListThreadsCommand:
    def __init__(self, manager, process):
        self.manager = manager
        self.process = process
        self.updated_thread_ids = []

    def complete(self, pending=None):
        threads = self.process.get_known_threads()
        current_threads = set(threads.keys())
        
        for thread_id in self.updated_thread_ids:
            if thread_id in current_threads:
                continue  # Do nothing, we're in sync
            
            Msg.warn(self, f"Resync: Was missing thread {thread_id}")
            system_objects = self.manager.get_system_objects()
            system_objects.set_current_thread_id(thread_id)
            tid = system_objects.get_current_thread_system_id()
            self.manager.thread_compute_if_absent(thread_id, self.process, tid)

        for id in list(current_threads):
            if id not in self.updated_thread_ids:
                Msg.warn(self, f"Resync: Had extra thread {id}")
                self.process.remove_thread(id)
                self.manager.remove_thread(id)

        return self.process.get_known_threads()

    def invoke(self):
        system_objects = self.manager.get_system_objects()
        system_objects.set_current_process_id(self.process.id)
        self.updated_thread_ids = list(system_objects.get_threads())
