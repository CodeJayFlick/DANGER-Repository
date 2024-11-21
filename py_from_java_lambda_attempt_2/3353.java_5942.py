Here's a translation of your Java code into equivalent Python:

```Python
class ProgramMergeManagerPlugin:
    def __init__(self):
        pass

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        self._provider = value

    def create_provider(self):
        # Create a new MergeManagerProvider instance with the current domain object name.
        return MergeManagerProvider(self, "Merge Programs for " + self.current_domain_object.name)

    def process_event(self, event):
        if isinstance(event, ProgramActivatedPluginEvent):
            active_program = (event).get_active_program()
            self.current_domain_object = active_program

    @property
    def current_domain_object(self):
        return self._current_domain_object

    @current_domain_object.setter
    def current_domain_object(self, value):
        self._current_domain_object = value

    def dispose(self):
        if hasattr(self.provider, 'dispose'):
            self.provider.dispose()

    def get_merge_manager(self):
        # Return the merge manager associated with this plug-in.
        return self.merge_manager

    @property
    def merge_manager(self):
        return self._merge_manager

    @merge_manager.setter
    def merge_manager(self, value):
        self._merge_manager = value

    def set_merge_component(self, component, component_id):
        if hasattr(self.provider, 'set_merge_component'):
            self.provider.set_merge_component(component, component_id)

    def update_merge_description(self, merge_description):
        if hasattr(self.provider, 'update_merge_description'):
            self.provider.update_merge_description(merge_description)

    def update_progress_details(self, progress_description):
        if hasattr(self.provider, 'update_progress_details'):
            self.provider.update_progress_details(progress_description)

    def set_current_progress(self, current_percent_progress):
        if hasattr(self.provider, 'set_current_progress'):
            self.provider.set_current_progress(current_percent_progress)

    def show_default_component(self):
        if hasattr(self.provider, 'show_default_component'):
            self.provider.show_default_component()

    def set_apply_enabled(self, state):
        if hasattr(self.provider, 'set_apply_enabled'):
            self.provider.set_apply_enabled(state)

    @property
    def get_provider(self):
        return self._provider

    def close_other_programs(self, ignore_changes=False):
        # Return False as the default behavior.
        return False

    def close_all_programs(self, ignore_changes=False):
        # Return False as the default behavior.
        return False

    def close_program(self, program=None, ignore_changes=False):
        # Return False as the default behavior.
        return False

    @property
    def all_open_programs(self):
        if self.merge_manager:
            program_merge_manager = (self.merge_manager)
            return [program_merge_manager.get_program(MergeConstants.RESULT),
                    program_merge_manager.get_program(MergeConstants.LATEST),
                    program_merge_manager.get_program(MergeConstants.MY),
                    program_merge_manager.get_program(MergeConstants.ORIGINAL)]
        else:
            return []

    @property
    def current_program(self):
        if self.current_domain_object:
            return (self.current_domain_object)
        else:
            return None

    def get_program(self, addr=None):
        # Return None as the default behavior.
        return None

    def search_priority(self, program):
        # Return 0 as the default priority.
        return 0

    @property
    def is_visible(self):
        if self.current_domain_object:
            return True
        else:
            return False

    def open_program(self, ghidra_url=None, state=0):
        # Return None as the default behavior.
        return None

    def open_program(self, domain_file=None):
        # Return None as the default behavior.
        return None

    def open_program(self, domain_file=None, dialog_parent=None):
        # Return None as the default behavior.
        return None

    @property
    def is_locked(self):
        if self.current_domain_object:
            return True
        else:
            return False

    def lock_down(self, state=False):
        pass


class MergeManagerProvider:

    def __init__(self, plugin, name):
        self.plugin = plugin
        self.name = name

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        self._provider = value

    def set_merge_component(self, component, component_id):
        # Set the merge component with the given ID.
        pass

    def update_merge_description(self, merge_description):
        # Update the merge description with the provided text.
        pass

    def update_progress_details(self, progress_description):
        # Update the progress details with the provided text.
        pass

    def set_current_progress(self, current_percent_progress):
        # Set the current progress percentage for the given component.
        pass

    def show_default_component(self):
        # Show the default merge component.
        pass

    def set_apply_enabled(self, state):
        # Enable or disable the Apply button based on the provided state.
        pass
```

Please note that Python does not support direct translation of Java code. The above Python code is a rewritten version of your original Java code in Python syntax and structure.