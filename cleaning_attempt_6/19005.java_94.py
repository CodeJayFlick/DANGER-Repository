from typing import Optional, List, Dict

class CommitAttempt:
    def __init__(self):
        self.commit_to_branch = None  # type: BranchName
        self.expected_head = Optional.empty()  # type: Optional[Hash]
        self.expected_states = {}  # type: Dict[ContentsId, Optional[ByteString]]
        self.puts = []  # type: List[Tuple[Key, str, bytes]]
        self.global = {}  # type: Dict[ContentsId, bytes]
        self.unchanged = []  # type: List[Key]
        self.deletes = []  # type: List[Key]
        self.commit_meta_serialized = None  # type: Optional[ByteString]

    @property
    def commit_to_branch(self):
        return self._commit_to_branch

    @commit_to_branch.setter
    def commit_to_branch(self, value):
        self._commit_to_branch = value

    @property
    def get_commit_to_branch(self):
        return self.commit_to_branch

    @property
    def expected_head(self):
        return self._expected_head

    @expected_head.setter
    def expected_head(self, value):
        self._expected_head = value

    @property
    def get_expected_head(self):
        return self.expected_head

    @property
    def expected_states(self):
        return self._expected_states

    @expected_states.setter
    def expected_states(self, value):
        self._expected_states = value

    @property
    def get_expected_states(self):
        return self.expected_states

    @property
    def puts(self):
        return self._puts

    @puts.setter
    def puts(self, value):
        self._puts = value

    @property
    def get_puts(self):
        return self.puts

    @property
    def global(self):
        return self._global

    @global.setter
    def global(self, value):
        self._global = value

    @property
    def get_global(self):
        return self.global

    @property
    def unchanged(self):
        return self._unchanged

    @unchanged.setter
    def unchanged(self, value):
        self._unchanged = value

    @property
    def get_unchanged(self):
        return self.unchanged

    @property
    def deletes(self):
        return self._deletes

    @deletes.setter
    def deletes(self, value):
        self._deletes = value

    @property
    def get_deletes(self):
        return self.deletes

    @property
    def commit_meta_serialized(self):
        return self._commit_meta_serialized

    @commit_meta_serialized.setter
    def commit_meta_serialized(self, value):
        self._commit_meta_serialized = value

    @property
    def get_commit_meta_serialized(self):
        return self.commit_meta_serialized
