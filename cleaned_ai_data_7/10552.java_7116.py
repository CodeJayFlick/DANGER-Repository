class StatusListener:
    def set_status_text(self, text):
        """Set the current status as type INFO"""
        pass  # Implement this method in your subclass

    def set_status_text(self, text: str, type: int) -> None:
        """Set the current status as the specified type"""
        pass  # Implement this method in your subclass

    def set_status_text(self, text: str, type: int, alert: bool) -> None:
        """Set the current status as the specified type with an optional alert"""
        pass  # Implement this method in your subclass

    def clear_status_text(self) -> None:
        """Clear the current status (same as set_status_text('') without being recorded)"""
        pass  # Implement this method in your subclass
