from datetime import timedelta

class AdjustableDatabaseAdapterConfig:
    def __init__(self):
        self.key_prefix = None
        self.parents_per_commit = 0
        self.key_list_distance = 0
        self.max_key_list_size = 0
        self.commit_timeout = timedelta()
        self.commit_retries = 0
        self.clock = None

    def with_key_prefix(self, key_prefix):
        self.key_prefix = key_prefix
        return self

    def with_parents_per_commit(self, parents_per_commit):
        self.parents_per_commit = parents_per_commit
        return self

    def with_key_list_distance(self, key_list_distance):
        self.key_list_distance = key_list_distance
        return self

    def with_max_key_list_size(self, max_key_list_size):
        self.max_key_list_size = max_key_list_size
        return self

    def with_commit_timeout(self, commit_timeout: timedelta):
        self.commit_timeout = commit_timeout
        return self

    def with_commit_retries(self, commit_retries):
        self.commit_retries = commit_retries
        return self

    def with_clock(self, clock):
        self.clock = clock
        return self
