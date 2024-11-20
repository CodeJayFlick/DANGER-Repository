class MultiFunctionComparisonProvider:
    def __init__(self, plugin):
        super().__init__(plugin, "functioncomparisonprovider", plugin.name)

    def get_component(self):
        if self.function_comparison_panel is None:
            self.function_comparison_panel = MultiFunctionComparisonPanel(self, tool)
        return self.function_comparison_panel

    def is_empty(self):
        return len(model.get_source_functions()) == 0


class FunctionComparisonProvider:
    pass


class DockingAction:
    pass


def init_function_comparison_panel(self):
    super().init_function_comparison_panel()

    next_function_action = NextFunctionAction(self)
    previous_function_action = PreviousFunctionAction(self)
    remove_functions_action = RemoveFunctionsAction(self)
    open_function_table_action = self.get_open_function_table_action()
    navigate_to_action = NavigateToFunctionAction(self)

    add_local_action(next_function_action)
    add_local_action(previous_function_action)
    add_local_action(remove_functions_action)
    add_local_action(open_function_table_action)
    add_local_action(navigate_to_action)


def get_open_function_table_action(self):
    return OpenFunctionTableAction(tool, self)


class MultiFunctionComparisonPanel:
    def __init__(self, provider, tool):
        pass


# Define the actions
class NextFunctionAction(DockingAction):
    def __init__(self, provider):
        super().__init__()


class PreviousFunctionAction(DockingAction):
    def __init__(self, provider):
        super().__init__()


class RemoveFunctionsAction(DockingAction):
    def __init__(self, provider):
        super().__init__()


class NavigateToFunctionAction(DockingAction):
    def __init__(self, provider):
        super().__init__()


# Define the actions for opening a table
class OpenFunctionTableAction(DockingAction):
    def __init__(self, tool, provider):
        super().__init__()
