class ListingFunctionGraphVertex:
    def __init__(self, controller, address_set, flow_type, is_entry):
        super().__init__(controller, controller.get_program(), address_set, flow_type, is_entry)

    @classmethod
    def copy_constructor(cls, controller, vertex):
        return cls(controller, vertex)

    def clone_vertex(self, new_controller):
        return ListingFunctionGraphVertex(new_controller, self)

    def has_loaded_component(self):
        return hasattr(self, 'component') and self.component is not None

    def get_component(self):
        if not hasattr(self, 'component'):
            system_utilities.assert_this_is_the_swing_thread("Cannot create vertex component off of the Swing thread")
            controller = self.get_controller()
            self.component = ListingGraphComponentPanel(self, controller, controller.get_tool(), self.get_program(), self.get_addresses())
            if hasattr(self, 'pending_restore_color') and self.pending_restore_color is not None:
                self.component.restore_color(self.pending_restore_color)
                self.pending_restore_color = None
        return self.component

    def dispose(self):
        super().dispose()
        if hasattr(self, 'component'):
            self.component.dispose()
            del self.component


class ListingGraphComponentPanel:
    pass  # This class is not defined in the provided Java code. It should be implemented separately.


def system_utilities_assert_this_is_the_swing_thread(message):
    print(f"Cannot create vertex component {message} off of the Swing thread")


# Note: The above Python code does not include any equivalent to the following Java imports:
#
# import ghidra.app.plugin.core.functiongraph.mvc.FGController;
# import ghidra.program.model.address.AddressSetView;
# import ghidra.program.model.symbol.FlowType;
# import ghidra.util.SystemUtilities;

# These would need to be replaced with Python equivalents or implemented separately.
