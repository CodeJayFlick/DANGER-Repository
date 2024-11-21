Here is a translation of the provided Java code into equivalent Python:

```Python
class JdiModelTargetBreakpointSpec:
    def __init__(self, breakpoints, info, is_element):
        self.info = info
        self.kinds = None  # Initialize kinds as None for now
        super().__init__(breakpoints, str(info), info, is_element)

    @property
    def enabled(self):
        return self.info.enabled

    @enabled.setter
    def enabled(self, value):
        if not isinstance(value, bool):
            raise ValueError("Enabled must be a boolean")
        self.info.enabled = value

    def delete(self):
        self.info.enabled = False  # Disable the breakpoint
        return None  # Return None to indicate successful deletion

    @property
    def kinds(self):
        return self.kinds

    @kinds.setter
    def kinds(self, value):
        if not isinstance(value, TargetBreakpointKindSet):
            raise ValueError("Kinds must be a TargetBreakpointKindSet")
        self._kinds = value  # Set the internal state of kinds

    def get_kinds(self):
        return self.kinds

    @property
    def actions(self):
        if not hasattr(self, '_actions'):
            self._actions = ListenerSet(TargetBreakpointAction)  # Initialize actions as a listener set
        return self._actions

    def add_action(self, action):
        self.actions.add(action)

    def remove_action(self, action):
        self.actions.remove(action)

    @property
    def info(self):
        return self.info

    @info.setter
    def info(self, value):
        if not isinstance(value, JdiBreakpointInfo):
            raise ValueError("Info must be a JdiBreakpointInfo")
        self._info = value  # Set the internal state of info

    def get_info(self, refresh=False):
        return CompletableFuture.completed_future(self.info)  # Return a completed future with the current breakpoint information

    @property
    def display(self):
        if not hasattr(self, '_display'):
            self._display = None  # Initialize display as None for now
        return self.display

    @display.setter
    def display(self, value):
        if not isinstance(value, str):
            raise ValueError("Display must be a string")
        self._display = value  # Set the internal state of display

    def update_attributes_from_info(self, reason):
        enabled = self.info.enabled
        kinds = compute_kinds(self.info)  # Compute and set the kinds based on breakpoint type
        change_attributes([], [], {'ENABLED_ATTRIBUTE_NAME': enabled, 'KINDS_ATTRIBUTE_NAME': kinds})  # Update attributes

    def update_info(self, old_info, new_info, reason):
        self.info = new_info  # Set the internal state of info to the new value
        self.update_attributes_from_info(reason)  # Update attributes based on the new breakpoint information
        return CompletableFuture.completed_future(None)  # Return a completed future with None

    def request_elements(self, refresh=False):
        if not hasattr(self, '_display'):
            self._display = None  # Initialize display as None for now
        return self.get_info(refresh).thenCompose(lambda i: self.update_info(self.info, i, "Refreshed"))  # Request elements and update breakpoint information

    def disable(self):
        self.info.enabled = False  # Disable the breakpoint
        return CompletableFuture.completed_future(None)  # Return a completed future with None to indicate successful disabling

    def enable(self):
        self.info.enabled = True  # Enable the breakpoint
        return CompletableFuture.completed_function(None)  # Return a completed function with None to indicate successful enabling

    @property
    def display_name(self):
        if not hasattr(self, '_display'):
            self._display = None  # Initialize display as None for now
        return self.display or super().get_display()  # Get the display name based on breakpoint information and default value