class LoadJob:
    def __init__(self, model: 'ThreadedTableModel', monitor):
        super().__init__(model, monitor)
        self.reload()  # set job to totally reload data;
        self.request_sort(model.get_sorting_context(), False)  # set the comparator so the data will be sorted

class TableUpdateJob:
    def __init__(self, model: 'ThreadedTableModel', monitor):
        pass

from abc import ABCMeta
import threading

class ThreadedTableModel(metaclass=ABCMeta): 
    @abstractmethod
    def get_sorting_context(self) -> object:
        pass

# Assuming these are Python classes and functions you would need to implement based on your actual requirements.
