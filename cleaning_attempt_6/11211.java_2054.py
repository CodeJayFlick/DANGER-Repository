class TransactionListener:
    def transaction_started(self, domain_obj: 'DomainObjectAdapterDB', tx):
        pass  # Implement this method in your subclass

    def transaction_ended(self, domain_obj: 'DomainObjectAdapterDB'):
        pass  # Implement this method in your subclass

    def undo_stack_changed(self, domain_obj: 'DomainObjectAdapterDB'):
        pass  # Implement this method in your subclass

    def undo_redo_occurred(self, domain_obj: 'DomainObjectAdapterDB'):
        pass  # Implement this method in your subclass
