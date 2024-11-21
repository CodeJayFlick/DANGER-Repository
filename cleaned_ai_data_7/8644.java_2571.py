class DiffControllerListener:
    def __init__(self):
        pass  # No initialization needed in this case

    def diff_location_changed(self, diff_control: 'ghidra_diff_controller', location: int) -> None:
        """Called when the difference location changes"""
        raise NotImplementedError("Method must be implemented by subclass")

    def differences_changed(self, diff_control: 'ghidra_diff_controller') -> None:
        """Called when the differences change"""
        raise NotImplementedError("Method must be implemented by subclass")
