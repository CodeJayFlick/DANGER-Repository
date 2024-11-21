Here is the translation of the given Java code into Python:

```Python
class DomainObjectTransactionManager:
    def __init__(self, domain_obj):
        self.domain_obj = domain_obj
        self.undo_list = []
        self.redo_list = []
        self.transaction_listeners = set()
        self.transaction = None

    @property
    def domain_object(self):
        return self.domain_obj

    @property
    def domain_objects(self):
        return [self.domain_obj]

    def check_domain_object(self, obj):
        if not isinstance(obj, DomainObjectAdapterDB) or obj != self.domain_obj:
            raise ValueError("Invalid domain object")

    def clear_transactions(self):
        self.undo_list.clear()
        self.redo_list.clear()

    def terminate_transaction(self, rollback=False, notify=True):
        with self.lock:
            if self.transaction is None or self.transaction_terminated:
                return
            try:
                self.domain_obj.dbh.terminate_transaction(self.transaction.id, not rollback)
                self.transaction.abort()
                self.transaction_terminated = True
                if self.domain_obj.change_set is not None:
                    self.domain_obj.change_set.end_transaction(not rollback)
                self.domain_obj.clear_cache(False)
            except Exception as e:
                self.domain_obj.error(e)

        self.domain_obj.fire_event(DomainObjectChangeRecord(DO_OBJECT_RESTORED))
        if notify:
            self.notify_end_transaction()

    def start_transaction(self, obj, description, listener=None, force=False, notify=True):
        if not isinstance(obj, DomainObjectAdapterDB) or obj != self.domain_obj:
            raise ValueError("Invalid domain object")

        if not force and self.transaction is None:
            verify_no_lock()
        elif self.transaction_terminated:
            Msg.warn(self, f"Aborted transaction still pending, new transaction will also be aborted: {description}")

        if self.transaction is None:
            self.transaction = DomainObjectDBTransaction(self.domain_obj.dbh.start_transaction(), self.domain_obj)
            if self.domain_obj.change_set is not None:
                self.domain_obj.change_set.start_transaction()
            return self.transaction.add_entry(description, listener)

    def end_transaction(self, obj, transaction_id, commit=True, notify=True):
        if not isinstance(obj, DomainObjectAdapterDB) or obj != self.domain_obj:
            raise ValueError("Invalid domain object")

        if self.transaction is None:
            raise ValueError("No transaction is open")

        try:
            returned_transaction = self.transaction
            status = self.transaction.status()
            if status == Transaction.COMMITTED:
                self.domain_obj.flush_write_cache()
                committed = self.domain_obj.dbh.end_transaction(transaction_id, True)
                if committed:
                    returned_transaction.has_committed_db_transaction = True
                    self.domain_obj.changed = True
                    self.redo_list.clear()
                    self.undo_list.append(self.transaction)
                    while len(self.undo_list) > NUM_UNDOS:
                        self.undo_list.pop(0)

            elif status == Transaction.ABORTED:
                if not self.transaction_terminated:
                    self.domain_obj.dbh.end_transaction(transaction_id, False)
                    if self.domain_obj.change_set is not None:
                        self.domain_obj.change_set.end_transaction(False)
                self.domain_obj.clear_cache(False)
        except Exception as e:
            self.transaction = None
            self.domain_obj.error(e)

    def get_undo_stack_depth(self):
        return len(self.undo_list)

    @property
    def can_redo(self):
        if self.transaction is None and len(self.redo_list) > 0:
            return self.domain_obj.dbh.can_redo()
        return False

    @property
    def can_undo(self):
        if self.transaction is None and len(self.undo_list) > 0:
            return self.domain_obj.dbh.can_undo()
        return False

    @property
    def redo_name(self):
        if self.transaction is None and len(self.redo_list) > 0:
            t = self.redo_list[-1]
            return t.description
        return ""

    @property
    def undo_name(self):
        if self.transaction is None and len(self.undo_list) > 0:
            t = self.undo_list[-1]
            return t.description
        return ""

    @property
    def current_transaction(self):
        return self.transaction

    def do_redo(self, notify=True):
        if self.can_redo():
            t = self.redo_list.pop()
            self.domain_obj.dbh.redo()
            self.domain_obj.clear_cache(False)
            if self.domain_obj.change_set is not None:
                self.domain_obj.change_set.redo()

            self.undo_list.append(t)
            t.restore_tool_states(False)

            if notify:
                self.notify_undo_redo()

    def do_undo(self, notify=True):
        if self.can_undo():
            t = self.undo_list.pop()
            t.init_after_state(self.domain_obj)
            self.domain_obj.dbh.undo()
            if self.domain_obj.change_set is not None:
                self.domain_obj.change_set.undo()

            self.redo_list.append(t)

            t.restore_tool_states(True)

            if notify:
                self.notify_undo_redo()

    def clear_undo(self, notify=True):
        while len(self.undo_list) > 0 or len(self.redo_list) > 0:
            self.undo_list.clear()
            self.redo_list.clear()

            if self.domain_obj.change_set is not None:
                self.domain_obj.change_set.clear_undo()

            if notify:
                self.notify_undo_stack_changed()

    def do_close(self, obj):
        pass

    def add_transaction_listener(self, obj, listener):
        if not isinstance(obj, DomainObjectAdapterDB) or obj != self.domain_obj:
            raise ValueError("Invalid domain object")

        self.transaction_listeners.add(listener)

    def remove_transaction_listener(self, obj, listener):
        if not isinstance(obj, DomainObjectAdapterDB) or obj != self.domain_obj:
            raise ValueError("Invalid domain object")

        self.transaction_listeners.remove(listener)
```

Please note that Python does not support direct translation of Java code. The above code is a manual translation and may require some adjustments to work correctly in your specific use case.