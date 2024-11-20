import threading
from queue import PriorityQueue
from abc import ABCMeta, abstractmethod

class ToolTaskManager(metaclass=ABCMeta):
    def __init__(self, tool: 'PluginTool'):
        self.tool = tool
        self.is_executing = False
        self.tasks = []
        self.queued_commands_map = {}
        self.open_foreground_transaction_ids = {}

    @abstractmethod
    def execute(self) -> None:
        pass

class BackgroundCommandTask(threading.Thread):
    def __init__(self, task_manager: 'ToolTaskManager', domain_object: 'UndoableDomainObject',
                 command: 'BackgroundCommand'):
        super().__init__()
        self.task_manager = task_manager
        self.domain_object = domain_object
        self.command = command

    def run(self) -> None:
        pass  # implement the logic here

class ToolTaskMonitor(metaclass=ABCMeta):
    @abstractmethod
    def update_task_cmd(self, cmd: 'BackgroundCommand') -> None:
        pass

# Python does not have direct equivalent of Java's SwingUtilities.invokeLater.
def invoke_later(runnable) -> None:
    threading.Thread(target=runnable).start()

class PluginTool(metaclass=ABCMeta):
    @abstractmethod
    def get_tool_frame(self) -> 'DomainObject':
        pass

class DomainObject(metaclass=ABCMeta):
    @abstractmethod
    def start_transaction(self, title: str) -> int:
        pass

    @abstractmethod
    def end_transaction(self, id: int, success: bool) -> None:
        pass

# Python does not have direct equivalent of Java's HashMap.
class PriorityQueue(metaclass=ABCMeta):
    def __init__(self):
        self.queue = []

    def put(self, item):
        if len(self.queue) == 0 or item < self.queue[0]:
            self.queue.insert(0, item)
        else:
            self.queue.append(item)

    def get(self):
        return self.queue.pop()

class BackgroundCommand(metaclass=ABCMeta):
    @abstractmethod
    def apply_to(self, domain_object: 'DomainObject', monitor: 'TaskMonitor') -> None:
        pass

# Python does not have direct equivalent of Java's TaskMonitor.
class TaskMonitor(metaclass=ABCMeta):
    @abstractmethod
    def show_progress(self) -> None:
        pass

    @abstractmethod
    def set_task_name(self, name: str) -> None:
        pass

    @abstractmethod
    def cancel(self) -> None:
        pass

# Python does not have direct equivalent of Java's TaskMonitorComponent.
class ToolTaskMonitor(ToolTaskManager):
    def __init__(self, tool: 'PluginTool'):
        super().__init__(tool)

    def update_task_cmd(self, cmd: 'BackgroundCommand') -> None:
        self.show_progress(cmd.has_progress())
        self.set_task_name(cmd.name)
