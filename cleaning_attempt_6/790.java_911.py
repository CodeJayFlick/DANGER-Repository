class DbgModelTargetThreadContainer:
    def get_target_thread(self, thread: 'DbgThread') -> 'DbgModelTargetThread':
        pass  # implement this method in your subclass

    def thread_created(self, thread: 'DbgThread'):
        pass  # implement this method in your subclass

    def thread_exited(self, thread_id: int):
        pass  # implement this method in your subclass
