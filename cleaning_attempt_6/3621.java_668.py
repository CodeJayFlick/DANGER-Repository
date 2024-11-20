class CreateArrayAction:
    DEFAULT_KEY_STROKE = KeyEvent.VK_OPEN_BRACKET
    CREATE_ARRAY_POPUP_MENU = ["Data", "Create Array..."]

    def __init__(self, plugin):
        super().__init__("Define Array", plugin.name)
        self.plugin = plugin

        popup_menu_data = MenuData(CREATE_ARRAY_POPUP_MENU, "BasicData")
        set_popup_menu(popup_menu_data)

        init_key_stroke(DEFAULT_KEY_STROKE)

        enable()

    def init_key_stroke(self, key_stroke):
        if not key_stroke:
            return
        self.set_key_binding(key_stroke)

    @property
    def enabled(self):
        return True

    def action_performed(self, context):
        program_action_context = ListingActionContext(context)
        program = program_action_context.get_program()
        location = program_action_context.get_location()
        selection = program_action_context.get_selection()

        if selection and not selection.is_empty():
            interior_sel = selection.get_interior_selection()
            if interior_sel:
                self.create_array_in_structure(program, interior_sel)
            else:
                self.create_array_from_selection(program, selection)

        elif location:
            component_path = location.get_component_path()
            if component_path and len(component_path) > 0:
                self.create_array_in_structure(program, location.get_address(), component_path)
            else:
                self.create_array_at_address(program, location.get_address())

    def create_array_in_structure(self, program, address, comp_path):
        tool = self.plugin.tool
        data = program.listing().get_data_containing(address)

        if not data:
            tool.set_status_info("Create Array Failed! No data at " + str(address))
            return

        component = None
        parent_type = None
        for i in range(len(comp_path)):
            comp = data.get_component(i)
            if isinstance(comp, Data):
                component = comp
                break

        if not component:
            tool.set_status_info("Create Array Failed! No data at " + str(address))
            return

        dt = component.data_type()
        parent_dt = component.parent().base_data_type()

        if not (isinstance(parent_dt, Structure)):
            tool.set_status_info("Cannot create array here")
            return

        max_elements = self.get_max_elements(parent_dt, comp_path.index(component), dt)
        num_elements = min(max_elements, len(range(len(comp_path))))

        cmd = CreateArrayCmd(address, num_elements, dt, component.length())
        if not tool.execute(cmd, program):
            tool.set_status_info(cmd.status_msg())

    def create_array_in_structure(self, program, interior_sel):
        tool = self.plugin.tool
        from_address = interior_sel.from()

        data = program.listing().get_data_at(from_address)
        if not data:
            tool.set_status_info("Create Array Failed! No data at " + str(from_address))
            return

        dt = data.data_type()
        length = data.length()
        num_elements = len(range(int(length / dt.length())))

        cmd = CreateArrayCmd(from_address, num_elements, dt, length)
        if not tool.execute(cmd, program):
            tool.set_status_info(cmd.status_msg())

    def get_max_no_conflict_elements(self, struct, index, dt):
        n = struct.num_components()
        length = 0
        while index < n:
            comp = struct.get_component(index)
            dtc = comp.data_type()
            if (dtc != DataType.DEFAULT) and (dtc != dt):
                break

            length += comp.length()

            index += 1

        return int(length / dt.length())

    def get_max_elements(self, struct, index, dt):
        n = struct.num_components()
        length = 0
        while index < n:
            comp = struct.get_component(index)
            length += comp.length()

            index += 1

        return int(length / dt.length())

    def create_array_at_address(self, program, address):
        tool = self.plugin.tool
        data = program.listing().get_data_at(address)

        if not data:
            tool.set_status_info("Create Array Failed! No data at " + str(address))
            return

        dt = data.data_type()
        length = data.length()

        max_no_conflict_elements = self.get_max_elements_that_fit(program, address, len(dt) * 8)
        num_elements = min(max_no_conflict_elements, int(length / (len(dt) * 8)))

        cmd = CreateArrayCmd(address, num_elements, dt, length)

        if not tool.execute(cmd, program):
            tool.set_status_info(cmd.status_msg())

    def create_array_from_selection(self, program, selection):
        tool = self.plugin.tool

        range = selection.get_first_range()
        address = selection.min_address()

        data = program.listing().get_data_at(address)
        if not data:
            tool.set_status_info("Create Array Failed! No data at " + str(address))
            return

        dt = data.data_type()
        length = len(range)

        num_elements = int(length / (len(dt) * 8))

        cmd = CreateArrayCmd(address, num_elements, dt, length)
        if not tool.execute(cmd, program):
            tool.set_status_info(cmd.status_msg())

    def get_num_elements(self, dt, max_no_conflict_elements, max_elements):
        dialog = NumberInputDialog("Create " + str(dt) + "[]", "Enter number of array elements (1 - {}) :".format(max_elements), 0, min(1, max_no_conflict_elements), max_elements)
        if not dialog.show():
            return int(min_value)

        value = dialog.get_value()
        if value > max_no_conflict_elements:
            result = OptionDialog.show_yes_no("Overwrite Existing Data?", "Existing data will be overridden if you create this array.\nAre you sure you want to continue?")
            if result != OptionDialog.YES_OPTION:
                return int(min_value)

        return value

    def get_max_elements_that_fit(self, program, address, element_size):
        block = program.memory().get_block(address)
        max_address = range.get_max_address()

        instruction_after = program.listing().get_instruction_after(address)
        if instruction_after and max_address > instruction_after.address():
            max_address = instruction_after.address() - 1

        length = int(max_address - address) + 1
        return min(length // element_size, len(range))

    def get_max_elements_ignore_existing(self, program, address, element_size):
        range_view = program.memory()
        range_ = range_view.get_range_containing(address)
        if not range_:
            return 0

        max_address = range_.get_max_address()

        instruction_after = program.listing().get_instruction_after(address)
        if instruction_after and max_address > instruction_after.address():
            max_address = instruction_after.address() - 1

        length = int(max_address - address) + 1
        return min(length // element_size, len(range_))

    def is_enabled_for_context(self, context):
        context_object = context.get_context_object()
        if isinstance(context_object, ListingActionContext):
            return self.plugin.is_create_data_allowed((ListingActionContext)(context_object))
        return False

class CreateArrayCmd:
    pass
