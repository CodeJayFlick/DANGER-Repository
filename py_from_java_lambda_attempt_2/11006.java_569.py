Here is the translation of the given Java code into equivalent Python:

```Python
import weakref

class DomainObjectDBTransaction:
    def __init__(self, id: int, domain_object):
        self.domain_object = domain_object
        self.id = id
        self.base_id = 1234
        self.list = []
        self.tool_states = {}
        self.active_entries = 0
        self.status = 'NOT_DONE'
        self.has_db_transaction = False

    def get_tool_states(self):
        if SystemUtilities.is_in_headless_mode():
            return
        for consumer in domain_object.get_consumer_list():
            if isinstance(consumer, PluginTool):
                tool_state = ToolStateFactory.create_tool_state(tool=consumer, domain_object=self.domain_object)
                self.tool_states[tool] = weakref.ref(tool_state)

    def restore_tool_states(self, before_state: bool):
        if not self.tool_states:
            return
        SystemUtilities.run_swing_later(lambda: 
            # flush events blocks so that current tool state and domain object are consistent prior to restore tool state
            self.domain_object.flush_events()
            if before_state:
                self.restore_tool_states_after_undo(self.domain_object)
            else:
                self.restore_tool_states_after_redo(self.domain_object))

    def get_next_base_id(self):
        return self.base_id

    def set_has_committed_db_transaction(self):
        if self.status != 'COMMITTED':
            raise ValueError("transaction was not committed")
        self.has_db_transaction = True

    @property
    def has_committed_db_transaction(self):
        return self.has_db_transaction

    def add_entry(self, description: str, listener=None) -> int:
        if listener is not None:
            self.aborted_transaction_listeners.add(listener)
        self.list.append(TransactionEntry(description))
        self.active_entries += 1
        self.base_id = self.get_next_base_id()
        return len(self.list)

    def end_entry(self, transaction_id: int, commit: bool):
        entry = self.list[transaction_id - self.base_id]
        if entry.status != 'NOT_DONE':
            raise ValueError("Transaction not found")
        entry.status = 'COMMITTED' if commit else 'ABORTED'
        if not commit:
            self.status = 'ABORTED'
        if --self.active_entries == 0 and self.status == 'NOT_DONE':
            self.status = 'COMMITTED'

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value: str):
        self._status = value

    def restore_tool_states_after_undo(self, domain_object):
        consumers = domain_object.get_consumer_list()
        for i in range(len(consumers)):
            obj = consumers[i]
            if isinstance(obj, PluginTool):
                tool_state = self.tool_states[tool]
                if tool_state is not None:
                    tool_state.restore_after_undo(domain_object)

    def restore_tool_states_after_redo(self, domain_object):
        consumers = domain_object.get_consumer_list()
        for i in range(len(consumers)):
            obj = consumers[i]
            if isinstance(obj, PluginTool):
                tool_state = self.tool_states[tool]
                if tool_state is not None:
                    tool_state.restore_after_redo(domain_object)

    @property
    def description(self) -> str:
        return "" if len(self.list) == 0 else self.domain_object.get_domain_file().get_name() + ": " + self.list[-1].description

    def get_open_sub_transactions(self):
        sub_tx_list = []
        for entry in self.list:
            if entry.status == 'NOT_DONE':
                sub_tx_list.append(entry.description)
        return sub_tx_list


class TransactionEntry:
    def __init__(self, description: str):
        self.description = description
        self.status = "NOT_DONE"


def init_after_state(self, domain_object):
    consumers = domain_object.get_consumer_list()
    for i in range(len(consumers)):
        obj = consumers[i]
        if isinstance(obj, PluginTool):
            tool_state = self.tool_states[tool]
            if tool_state is not None:
                tool_state.get_after_state(domain_object)


def abort(self):
    self.status = "ABORTED"
    for listener in self.aborted_transaction_listeners:
        listener.transaction_aborted(id=self.id)
    self.aborted_transaction_listeners.clear()


class AbortedTransactionListener(weakref.WeakReference):
    def transaction_aborted(self, id: int):
        pass


def run_swing_later(func):
    # implementation of this function is not provided
    pass

def flush_events():
    # implementation of this function is not provided
    pass
```

Please note that the above Python code does not include all the necessary imports and implementations.