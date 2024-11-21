import ghidra.app.plugin.core.scalartable as scalartable
from ghidra.util import HelpLocation
from ghidra.program.model.listing import Program
from ghidra.framework.model import DomainObjectChangedEvent, ChangeManager

class ScalarSearchPlugin:
    def __init__(self):
        self.search_action = None
        self.providers = set()

    @property
    def reload_update_mgr(self):
        return SwingUpdateManager(1000, 60000)

    def init(self):
        # Initialize the plugin here.
        pass

    def dispose(self):
        if hasattr(self, 'current_program'):
            self.current_program.remove_listener(self)
        for provider in list(self.providers):
            provider.dispose()
            self.providers.discard(provider)

    def domain_object_changed(self, event: DomainObjectChangedEvent) -> None:
        # Check the type of change and update providers accordingly.
        if (event.contains_event(DomainObject.DO_OBJECT_RESTORED) or
                event.contains_event(ChangeManager.DOCR_CODE_ADDED) or
                event.contains_event(ChangeManager.DOCR_CODE_REMOVED)):
            self.reload_update_mgr.update()

    def program_activated(self, program: Program):
        # Add the plugin as a listener for this program.
        if hasattr(program, 'add_listener'):
            program.add_listener(self)

    def program_closed(self, program: Program) -> None:
        # Remove the plugin from the list of listeners and clean up any providers
        if hasattr(program, 'remove_listener'):
            program.remove_listener(self)
        self.providers = {provider for provider in self.providers if provider.get_program() != program}

    def open_search_dialog(self):
        dialog = ScalarSearchDialog()
        dialog.show()

    def create_actions(self) -> None:
        # Create the search action and add it to the plugin.
        self.search_action = NavigatableContextAction("Search for Scalars", "Scalar Search")
        self.search_action.set_help_location(HelpLocation(self, "Scalar_Search"))
        self.search_action.add_to_window_when(NavigatableActionContext)
