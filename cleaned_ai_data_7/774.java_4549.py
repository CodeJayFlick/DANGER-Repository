from abc import ABC, abstractmethod


class DbgModelTargetProcess(ABC):
    def process_started(self, pid: int) -> None:
        pass  # implement this method in subclass

    @abstractmethod
    def get_threads(self) -> 'DbgModelTargetThreadContainer':
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_modules(self) -> 'DbgModelTargetModuleContainer':
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_memory(self) -> 'DbgModelTargetMemoryContainer':
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def thread_state_changed_specific(self, thread: 'DbgThread', state: int) -> None:
        pass  # implement this method in subclass

    def get_process(self) -> 'DbgProcess':
        manager = self.get_manager()
        so = manager.get_system_objects()
        try:
            index = PathUtils.parse_index(self.name)
            pid = int(index, 10)
            id = so.get_process_id_by_system_id(pid)
            if id is None:
                id = so.get_current_process_id()
            return manager.get_process_compute_if_absent(id, pid)
        except ValueError as e:
            return manager.get_current_process()

    @abstractmethod
    def set_active(self) -> 'CompletableFuture[Void]':
        raise NotImplementedError("Method not implemented")


class DbgProcess:
    pass


class DbgThread:
    pass


class DbgModelTargetThreadContainer:
    pass


class DbgModelTargetModuleContainer:
    pass


class DbgModelTargetMemoryContainer:
    pass
