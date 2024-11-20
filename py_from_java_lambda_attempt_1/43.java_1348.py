Here is the translation of the given Java code into Python:

```Python
class DebuggerTrackLocationTrait:
    def __init__(self):
        self.config_state_handler = AutoConfigStateHandler(DebuggerTrackLocationTrait)
        self.listener = ForTrackingListener()
        self.color_model = ColorModel(self.plugin, self.component_provider)
        self.selection_generator = TrackSelectionGenerator()

    @property
    def tracked_location(self):
        return self._tracked_location

    @tracked_location.setter
    def tracked_location(self, value):
        self._tracked_location = value

    def get_background_color_model(self):
        return self.color_model

    def create_listing_background_color_model(self, listing_panel):
        return ListingColorModel(listing_panel)

    def get_selection_generator(self):
        return self.selection_generator

    @property
    def spec(self):
        return self._spec

    @spec.setter
    def spec(self, value):
        if self.spec != value:
            self._spec = value
            self.spec_changed()

    def set_spec(self, spec):
        action.current_action_state_by_user_data(spec)

    def get_spec(self):
        return self.spec

    def install_action(self):
        action = DebuggerTrackLocationAction.builder(self.plugin).on_action(
            lambda ctx: self.do_track()
        ).on_action_state_changed(
            lambda new_state, trigger: self.do_set_spec(new_state.user_data)
        )
        .build_and_install_local(self.component_provider)

        return action

    def do_track(self):
        if not same_coordinates(current.view, current.get_view()):
            tracked_location = compute_tracked_location()
            location_tracked()

    def clicked_spec_button(self, ctx):
        self.do_track()

    def clicked_spec_menu(self, new_state, trigger):
        self.do_set_spec(new_state.user_data)

    def do_set_spec(self, spec):
        if self.spec != spec:
            self.spec = spec
            self.spec_changed()
        self.do_track()

    @property
    def current(self):
        return self._current

    @current.setter
    def current(self, value):
        self._current = value

    def go_to_coordinates(self, coordinates):
        if same_coordinates(current.view, coordinates.get_view()):
            current = coordinates
            return
        do_listeners = not (current.trace == coordinates.get_trace())
        if do_listeners:
            remove_old_listeners()
        current = coordinates
        if do_listeners:
            add_new_listeners()

    def write_config_state(self, save_state):
        self.config_state_handler.write_config_state(self, save_state)

    def read_config_state(self, save_state):
        self.config_state_handler.read_config_state(self, save_state)
        action.current_action_state_by_user_data(spec)


class ForTrackingListener:
    def __init__(self):
        pass

    def registers_changed(self, space, range, old_value, new_value):
        if current.view is None or spec is None:
            return
        if not spec.affected_by_register_change(space, range, current):
            return
        self.do_track()

    def stack_changed(self, stack):
        if current.view is None or spec is None:
            return
        if not spec.affected_by_stack_change(stack, current):
            return
        self.do_track()


class ColorModel:
    def __init__(self, plugin, component_provider):
        pass

    @property
    def tracked_location(self):
        return self._tracked_location


class TrackSelectionGenerator:
    def __init__(self):
        pass

    def add_selections(self, layout_index, translator, selections):
        if tracked_location is None or tracking_color is None:
            return
        field_sel = translator.convert_address_to_field(tracked_location.get_address())
        selections.add(ColoredFieldSelection(field_sel, tracking_color))


class ListingColorModel:
    def __init__(self, listing_panel):
        pass

    @property
    def tracked_location(self):
        return self._tracked_location


def compute_tracked_location():
    # Change of register values (for current frame)
    # Change of stack pc (for current frame)
    # Change of current view (if not caused by goTo)
    # Change of current thread
    # Change of current snap
    # Change of current frame
    # Change of tracking settings

    cur = current
    if cur.thread is None or spec is None:
        return null
    address = spec.compute_trace_address(tool, cur, cur.view.get_snap())
    return ProgramLocation(cur.view, address) if address else null


def location_tracked():
    pass


def spec_changed():
    pass

# TODO: This may already be deprecated....