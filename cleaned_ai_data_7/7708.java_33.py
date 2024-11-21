import ghidra.app.plugin.PluginCategoryNames
from ghidra.program.model.address import Address
from ghidra.util.HelpLocation import HelpLocation
from ghidra.framework.options import OptionsChangeListener, ToolOptions
from ghidra.graph.viewer.options import VisualGraphOptions

class FunctionCallGraphPlugin:
    def __init__(self):
        self.provider = None
        self.vg_options = VisualGraphOptions()

    @property
    def name(self):
        return "Function Call Graph"

    @property
    def show_provider_action_name(self):
        return "Display Function Call Graph"

    @property
    def default_help(self):
        return HelpLocation("FunctionCallGraphPlugin", self.name)

    def init(self, tool):
        self.provider = FcgProvider(tool, self)
        self.create_actions()
        self.initialize_options()

    def initialize_options(self):
        options = tool.get_options(ToolConstants.GRAPH_OPTIONS)
        options.add_listener(self)
        help_location = HelpLocation(self.name, "Options")
        call_graph_options = options.get_options(self.name)
        self.vg_options.register_options(call_graph_options, help_location)
        self.vg_options.load_options(call_graph_options)
        self.provider.options_changed()

    def options_changed(self, tool_options, option_name, old_value, new_value):
        if not isinstance(tool_options, ToolOptions) or \
           not isinstance(option_name, str) or \
           not (isinstance(old_value, object) and isinstance(new_value, object)):
            raise OptionsVetoException
        call_graph_options = options.get_options(self.name)
        self.vg_options.load_options(call_graph_options)
        self.provider.options_changed()

    def write_config_state(self, state):
        self.provider.write_config_state(state)

    def read_config_state(self, state):
        self.provider.read_config_state(state)

    def location_changed(self, loc):
        if not isinstance(loc, ProgramLocation):
            raise ValueError
        self.location_updater.update()
        self.do_location_changed()

    def do_location_changed(self):
        self.provider.location_changed(self.current_location())

    def handle_provider_location_changed(self, location):
        # For snapshots
        #if provider != connectedProvider:
        #   return

        if not isinstance(location, ProgramLocation):
            raise ValueError

        go_to_service = tool.get_service(GoToService)
        if go_to_service is None:
            return

        self.system_utilities.run_swing_later(lambda: go_to_service.go_to(location))

    def dispose(self):
        self.provider.dispose()

    def create_actions(self, tool):
        show_provider_action = DockingAction(self.show_provider_action_name, self.name)
        show_provider_action.action_performed = lambda context: self.provider.set_visible(True)

        # TODO Create icon from scratch
        #icon = ResourceManager.load_image("images/applications-development.png")
        #show_provider_action.set_tool_bar_data(ToolBarData(icon, "View"))
        tool.add_action(show_provider_action)

    def show_provider(self):
        self.provider.set_visible(True)

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        if not isinstance(value, FcgProvider):
            raise ValueError
        self._provider = value

    @property
    def current_address(self):
        if self.current_location is None:
            return Address()
        return self.current_location.get_address()

    @property
    def current_location(self):
        return self._current_location

    @current_location.setter
    def current_location(self, value):
        if not isinstance(value, ProgramLocation):
            raise ValueError
        self._current_location = value

    @property
    def options(self):
        return self.vg_options
