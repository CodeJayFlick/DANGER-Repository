import logging

class CommittedEntryManager:
    def __init__(self, max_num_of_log_in_mem):
        self.entries = []
        self.entry_total_mem_size = 0
        for _ in range(max_num_of_log_in_mem):
            self.entries.append(EmptyContentLog(-1, -1))
    
    def applying_snapshot(self, snapshot):
        local_index = self.get_dummy_index()
        snap_index = snapshot.last_log_index
        if local_index >= snap_index:
            logging.info("requested snapshot is older than the existing snapshot")
            return
        
        self.entries.clear()
        self.entries.append(EmptyContentLog(snap_index, snapshot.last_log_term))
    
    def get_dummy_index(self):
        return self.entries[0].curr_log_index
    
    def get_first_index(self):
        return self.get_dummy_index() + 1
    
    def get_last_index(self):
        return self.get_dummy_index() + len(self.entries) - 1
    
    def total_size(self):
        # the first one is a sentry
        return len(self.entries) - 1
    
    @staticmethod
    def maybe_term(index, entries):
        log = None if index < 0 else entries[index]
        if log:
            return log.curr_log_term
        
        return -1
    
    def get_entries(self, low, high):
        if low > high:
            logging.debug("invalid getEntries: parameter: {} > {}", low, high)
            return []
        
        dummy_index = self.get_dummy_index()
        if low <= dummy_index:
            logging.debug("entries low ({}) is out of bound dummyIndex ({}), adjust parameter 'low' to {}", low, dummy_index, dummy_index + 1)
            low = dummy_index + 1
        
        last_index = self.get_last_index()
        if high > last_index + 1:
            logging.debug("entries high ({}) is out of bound lastIndex ({}), adjust parameter 'high' to {}", high, last_index, last_index + 1)
            high = last_index + 1
        
        return [log for log in entries[low - dummy_index:high - dummy_index]]
    
    def get_entry(self, index):
        if index < self.get_dummy_index():
            logging.debug("invalid committedEntryManager getEntry: parameter: {} < {}", index, self.get_dummy_index())
            raise EntryCompactedException(index, self.get_dummy_index())
        
        return None if (index - self.get_dummy_index()) >= len(self.entries) else self.entries[index - dummy_index]
    
    def compact_entries(self, compact_index):
        dummy_index = self.get_dummy_index()
        if compact_index < dummy_index:
            logging.info("entries before request index ({}) have been compacted, and the compactIndex is ({})", compact_index, dummy_index)
            return
        
        if compact_index > self.get_last_index():
            raise EntryUnavailableException(compact_index, self.get_last_index())
        
        for i in range(1, (compact_index - dummy_index) + 1):
            self.entry_total_mem_size -= self.entries[i].byte_size
        self.entries[0] = EmptyContentLog(self.entries[(compact_index - dummy_index)].curr_log_index, self.entries[(compact_index - dummy_index)].curr_log_term)
        self.entries[1:(compact_index - dummy_index) + 1].clear()
    
    def append(self, appending_entries):
        if not appending_entries:
            return
        
        offset = appending_entries[0].curr_log_index - self.get_dummy_index()
        if len(self.entries) - offset == 0:
            for log in appending_entries:
                self.entry_total_mem_size += log.byte_size
            self.entries.extend(appending_entries)
        
        elif len(self.entries) - offset > 0:
            raise TruncateCommittedEntryException(appending_entries[0].curr_log_index, self.get_last_index())
        
        else:
            logging.error("missing log entry [last: {}, append at: {}]", self.get_last_index(), appending_entries[0].curr_log_index)
    
    @TestOnly
    def __init__(self, entries):
        self.entries = entries
    
    @TestOnly
    def get_all_entries(self):
        return self.entries
    
    @property
    def entry_total_mem_size(self):
        return self._entry_total_mem_size
    
    @entry_total_mem_size.setter
    def entry_total_mem_size(self, value):
        self._entry_total_mem_size = value
    
    def max_log_num_should_reserve(self, max_mem_size):
        total_size = 0
        for i in range(len(self.entries) - 1, -1, -1):
            if total_size + self.entries[i].byte_size > max_mem_size:
                return len(self.entries) - 1 - i
        
        return len(self.entries) - 1


class EmptyContentLog:
    def __init__(self, curr_log_index, curr_log_term):
        self.curr_log_index = curr_log_index
        self.curr_log_term = curr_log_term
    
    @property
    def byte_size(self):
        # This method should be implemented based on the actual log size calculation.
        return 0
    
    @property
    def curr_log_index(self):
        return self._curr_log_index
    
    @curr_log_index.setter
    def curr_log_index(self, value):
        self._curr_log_index = value
    
    @property
    def curr_log_term(self):
        return self._curr_log_term
    
    @curr_log_term.setter
    def curr_log_term(self, value):
        self._curr_log_term = value


class EntryCompactedException(Exception):
    pass


class TruncateCommittedEntryException(Exception):
    pass

class LogManagerMeta:
    # This class should be implemented based on the actual log manager meta.
    pass
