class NextRangeAction:
    def __init__(self, tool, name, owner, nav_options):
        self.tool = tool
        self.nav_options = nav_options
        super().__init__(name, owner)
        self.set_enabled(False)

    def is_enabled_for_context(self, context):
        current_address = context.get_address()
        selection = self.get_selection(context)
        if not selection or not selection:
            return False

        cu = context.get_program().get_listing().get_code_unit_at(current_address)
        if cu:
            current_address = cu.get_max_address()

        last_range = selection.get_last_range()
        max_address = (
                nav_options.is_goto_top_and_bottom_of_range_enabled() and
                last_range.get_max_address() or
                last_range.get_min_address()
        )
        return current_address < max_address

    def action_performed(self, context):
        go_to_address = self.get_go_to_address(context)
        service = self.tool.get_service(GoToService())
        if service:
            service.go_to(context.get_navigatable(), go_to_address)

    def get_go_to_address(self, context):
        selection = self.get_selection(context)
        current_address = context.get_address()
        max_address = current_address

        cu = context.get_code_unit()
        if cu:
            max_address = cu.get_max_address()

        it = selection.get_address_ranges(current_address, True)
        while it.has_next():
            range_ = it.next()
            if range_.contains(current_address):
                if self.nav_options.is_goto_top_and_bottom_of_range_enabled() and not current_address == range_.get_max_address() and max_address != range_.get_max_address():
                    return range_.get_max_address()

                if not it.has_next():
                    return current_address

        return range_.get_min_address()

    def get_selection(self, context):
        # This method should be implemented in the subclass
        pass


class ProgramLocationActionContext:
    def __init__(self, address, code_unit=None):
        self.address = address
        self.code_unit = code_unit

    def get_address(self):
        return self.address

    def get_code_unit(self):
        return self.code_unit


class GoToService:
    pass


# Example usage:

tool = PluginTool()
nav_options = NavigationOptions()

action = NextRangeAction(tool, "Next Range Action", "Owner", nav_options)
context = ProgramLocationActionContext(0x10000000)

print(action.is_enabled_for_context(context))  # This will print False
action.action_performed(context)  # Assuming the service is available and implemented correctly

