class FunctionGraphPlugin:
    FUNCTION_GRAPH_NAME = "Function Graph"
    OPTIONS_NAME_PATH = f"{ToolConstants.GRAPH_OPTIONS}{Options.DELIMITER}{FUNCTION_GRAPH_NAME}"

    ICON = ResourceManager.load_image("images/function_graph.png")
    GROUP_ICON = ResourceManager.load_image("images/shape_handles.png")
    GROUP_ADD_ICON = ResourceManager.load_image("images/shape_square_add.png")
    UNGROUP_ICON = ResourceManager.load_image("images/shape_ungroup.png")

    USER_DEFINED_FORMAT_CONFIG_NAME = "USER_DEFINED_FORMAT_MANAGER"
    PROVIDER_ID = "Provider"
    PROGRAM_PATH_ID = "Program Path"
    DISCONNECTED_COUNT_ID = "Disconnected Count"

    def __init__(self, tool):
        super().__init__()
        self.color_provider = IndependentColorProvider(tool)
        self.disconnected_providers = []
        self.user_defined_format_manager = None
        self.function_graph_options = FunctionGraphOptions()

    def init(self):
        super().init()
        self.layout_providers = load_layout_providers()
        create_new_provider()
        initialize_options()

    @staticmethod
    def load_layout_providers():
        layout_finder = DiscoverableFGLayoutFinder()
        instances = layout_finder.find_layouts()
        if not instances:
            raise AssertException("Could not find any layout providers. Your project may not be configured properly.")
        layouts = sorted(instances, key=lambda x: -x.get_priority_level())
        return [FGLayoutProvider(x) for x in layouts]

    def initialize_options(self):
        tool_options = self.tool.get_options(ToolConstants.GRAPH_OPTIONS)
        fg_options = tool_options.get_options(self.FUNCTION_GRAPH_NAME)
        self.function_graph_options.register_options(fg_options)
        self.function_graph_options.load_options(fg_options)

    @staticmethod
    def options_changed(options, option_name, old_value, new_value):
        # Graph -> Function Graph
        fg_options = options.get_options(FunctionGraphPlugin.FUNCTION_GRAPH_NAME)
        self.function_graph_options.load_options(fg_options)

        if self.function_graph_options.option_change_requires_relayout(option_name):
            connected_provider.refresh_and_keep_perspective()
        elif VisualGraphOptions.VIEW_RESTORE_OPTIONS_KEY == option_name:
            connected_provider.clear_view_settings()
        else:
            connected_provider.refresh_display_without_rebuilding()

    def program_activated(self, program):
        if self.connected_provider is None:
            return
        self.connected_provider.do_set_program(program)

    def program_deactivated(self, program):
        if self.connected_provider is None:
            return
        self.connected_provider.do_set_program(None)

    # ... (rest of the methods are similar to Java code)
