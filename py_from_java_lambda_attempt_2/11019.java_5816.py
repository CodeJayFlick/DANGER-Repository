Here is the translation of the given Java code into Python:

```Python
class SynchronizedTransaction:
    def __init__(self, managers):
        self.managers = managers
        self.hold_transaction_ids = [0] * len(managers)
        self.has_changes = [False] * len(managers)
        self.descriptions = [''] * len(managers)
        self.active_counts = [0] * len(managers)
        self.id = DomainObjectDBTransaction.get_next_base_id()
        
        for i in range(len(managers)):
            manager = managers[i]
            hold_transaction_ids[i] = manager.start_transaction(manager.get_domain_object(), '', None, False, False)
            
    def get_description(self):
        buf = ''
        for i in range(len(self.managers)):
            if self.descriptions[i]:
                if len(buf) != 0:
                    buf += '\n'
                buf += self.get_domain_object_name(self.managers[i])
                buf += ': '
                buf += self.descriptions[i]
                
        return buf
    
    def get_domain_object_name(self, manager):
        domain_object = manager.get_domain_object()
        return domain_object.get_domain_file().get_name()

    @property
    def id_(self):
        return self.id

    def get_open_sub_transactions(self):
        list_ = []
        
        if self.status == SynchronizedTransaction.ABORTED or self.status == SynchronizedTransaction.COMMITTED:
            return list_
            
        for i in range(len(self.managers)):
            name = self.get_domain_object_name(self.managers[i])
            for str_ in self.managers[i].get_current_transaction().get_open_sub_transactions():
                list_.append(name + ': ' + str_)
                
        return list_

    @property
    def is_active_(self):
        for active_count in self.active_counts:
            if active_count != 0:
                return True
                
        return False

    @property
    def status(self):
        if self.status == SynchronizedTransaction.ABORTED and self.is_active_():
            return SynchronizedTransaction.NOT_DONE_BUT_ABORTED
            
        return self.status
    
    def add_entry(self, domain_obj, description, listener):
        index = self.find_domain_object(domain_obj)
        
        tx_id = self.managers[index].start_transaction(domain_obj, description, listener, False, False)
        self.active_counts[index] += 1
        
        if not self.descriptions[index] and description:
            self.descriptions[index] = description
            
        return tx_id

    def end_entry(self, domain_obj, transaction_id, commit):
        index = self.find_domain_object(domain_obj)
        
        self.managers[index].end_transaction(domain_obj, transaction_id, commit, False)
        
        if not commit:
            self.status = SynchronizedTransaction.ABORTED
            
        else:
            self.status = SynchronizedTransaction.COMMITTED
        
        self.active_counts[index] -= 1
        
        if not self.is_active_ and self.status == SynchronizedTransaction.NOT_DONE:
            self.status = SynchronizedTransaction.COMMITTED

    def find_domain_object(self, domain_obj):
        for i in range(len(self.managers)):
            if self.managers[i].get_domain_object() == domain_obj:
                return i
                
        raise ValueError("unknown domain object")

    def end_all(self, commit):
        has_change = False
        
        for i in range(len(self.managers)):
            transaction = self.managers[i].end_transaction(self.managers[i].get_domain_object(), 
                                                            self.hold_transaction_ids[i], commit, False)
            
            if commit and transaction.has_committed_db_transaction():
                self.has_changes[i] = True
                has_change = True
                
            else:
                self.descriptions[i] = ''
                
        return has_change

    def redo(self):
        for i in range(len(self.managers)):
            if self.has_changes[i]:
                self.managers[i].do_redo(False)
                
    def undo(self):
        for i in range(len(self.managers)):
            if self.has_changes[i]:
                self.managers[i].do_undo(False)

    @property
    def has_committed_db_transaction_(self):
        for i in range(len(self.managers)):
            if self.has_changes[i]:
                return True
                
        return False

SynchronizedTransaction.ABORTED = 0
SynchronizedTransaction.COMMITTED = 1
SynchronizedTransaction.NOT_DONE = 2
SynchronizedTransaction.NOT_DONE_BUT_ABORTED = 3