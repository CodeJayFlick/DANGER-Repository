class NoTransactionException(Exception):
    def __init__(self):
        super().__init__("Transaction has not been started")
