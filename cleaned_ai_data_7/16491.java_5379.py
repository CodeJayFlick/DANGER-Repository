class StableEntryManager:
    def __init__(self):
        pass

    def get_all_entries_after_applied_index(self) -> list:
        raise NotImplementedError("Method not implemented")

    def get_all_entries_after_committed_index(self) -> list:
        raise NotImplementedError("Method not implemented")

    def append(self, entries: list, max_have_applied_commit_index: int):
        raise NotImplementedError("Method not implemented")

    def flush_log_buffer(self):
        raise NotImplementedError("Method not implemented")

    def force_flush_log_buffer(self):
        raise NotImplementedError("Method not implemented")

    def remove_compacted_entries(self, index: int):
        raise NotImplementedError("Method not implemented")

    def set_hard_state_and_flush(self, state) -> None:
        raise NotImplementedError("Method not implemented")

    def get_hard_state(self) -> object:
        raise NotImplementedError("Method not implemented")

    def get_meta(self) -> object:
        raise NotImplementedError("Method not implemented")

    def get_logs(self, start_index: int, end_index: int) -> list:
        raise NotImplementedError("Method not implemented")

    def close(self):
        pass

    def clear_all_logs(self, commit_index: int) -> None:
        raise NotImplementedError("Method not implemented")
