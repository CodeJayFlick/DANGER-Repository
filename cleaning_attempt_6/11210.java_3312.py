class Transaction:
    NOT_DONE = 0
    COMMITTED = 1
    ABORTED = 2
    NOT_DONE_BUT_ABORTED = 3

    def get_id(self):
        pass  # method to be implemented by subclass

    @property
    def description(self):
        pass  # property getter, method to be implemented by subclass

    @property
    def open_sub_transactions(self):
        return []  # list of strings representing sub-transactions

    def get_status(self):
        pass  # method to be implemented by subclass

    def has_committed_db_transaction(self):
        pass  # method to be implemented by subclass
