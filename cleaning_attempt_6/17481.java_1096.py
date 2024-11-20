class ManagedSeriesReader:
    def is_managed_by_query_manager(self) -> bool:
        pass  # To be implemented by subclasses

    def set_managed_by_query_manager(self, managed_by_query_manager: bool):
        pass  # To be implemented by subclasses

    def has_remaining(self) -> bool:
        pass  # To be implemented by subclasses

    def set_has_remaining(self, has_remaining: bool):
        pass  # To be implemented by subclasses
