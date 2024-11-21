class VersionedDBListener:
    def __init__(self):
        pass

    def versions_changed(self, min_version: int, current_version: int) -> None:
        """Available database versions have been modified."""
        pass  # Implement this method in your subclass

    def version_created(self, db: 'VersionedDatabase', version: int, time: float, comment: str, checkin_id: int) -> bool:
        """A new database version has been created."""
        return True  # Default implementation; override in your subclass if needed

    def version_deleted(self, version: int) -> None:
        """A version has been deleted."""
        pass  # Implement this method in your subclass

    def get_checkout_version(self, checkout_id: int) -> int:
        """Returns the checkout version associated with the specified checkoutId."""
        return -1  # Default implementation; override in your subclass if needed

    def checkin_completed(self, checkout_id: int) -> None:
        """Terminate the specified checkout."""
        pass  # Implement this method in your subclass
