class RecorderPermanentTransaction:
    @staticmethod
    def start(obj: 'ghidra.framework.model.UndoableDomainObject', description: str) -> 'RecorderPermanentTransaction':
        tid = UndoableTransaction.start(obj, description, True)
        return RecorderPermanentTransaction(obj, tid)

    def __init__(self, obj: 'ghidra.framework.model.UndoableDomainObject', tid):
        self.obj = obj
        self.tid = tid

    def close(self) -> None:
        self.tid.close()
        self.obj.clear_undo()

class UndoableTransaction:
    @staticmethod
    def start(obj, description, commit=True):
        # Implement the logic for starting a transaction here.
        pass

class UndoableDomainObject:
    def clear_undo(self):
        # Implement the logic to clear undo here.
        pass
