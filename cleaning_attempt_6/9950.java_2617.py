class WizardPanelListener:
    def validity_changed(self):
        """Notification that something on the panel changed."""
        pass  # Implement this method in your subclass

    def set_status_message(self, msg: str) -> None:
        """Notification to set a status message.
        
        Args:
            msg (str): The message
        """
        pass  # Implement this method in your subclass
