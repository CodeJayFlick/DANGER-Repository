Here is the translation of the given Java code into Python:

```Python
class FallThroughModel:
    def __init__(self, tool, program, address):
        self.program = program
        self.tool = tool
        self.current_addr = None
        self.current_fallthrough_addr = None
        self.default_fallthrough_addr = None
        self.is_user_defined = False
        self.is_default = True
        self.message = ""
        self.executing_command = False
        self.cu_format = BrowserCodeUnitFormat(tool)

    def set_change_listener(self, listener):
        self.listener = listener

    def set_home_address(self, address):
        inst = self.program.get_listing().get_instruction_at(address)
        if inst is None:
            return
        self.current_addr = inst.min_address()
        self.current_fallthrough_addr = inst.fall_through()
        self.default_fallthrough_addr = inst.default_fall_through()
        self.is_user_defined = not inst.is_fall_through_overridden()
        self.is_default = not self.is_user_defined
        self.listener.state_changed(None)

    def get_address(self):
        if self.current_addr is None or \
           self.program.get_listing().get_instruction_containing(self.current_addr) is None:
            self.current_addr = None
        return self.current_addr

    def get_current_fallthrough(self):
        return self.current_fallthrough_addr

    def set_current_fallthrough(self, addr):
        if self.is_user_defined and not self.executing_command:
            self.current_fallthrough_addr = addr
            self.listener.state_changed(None)

    def default_selected(self):
        self.is_default = True
        self.is_user_defined = False
        self.current_fallthrough_addr = self.default_fallthrough_addr
        self.listener.state_changed(None)

    def user_selected(self):
        self.is_default = False
        self.is_user_defined = True
        self.current_fallthrough_addr = None
        self.listener.state_changed(None)

    def is_default_fallthrough(self):
        return self.is_default

    def is_user_defined_fallthrough(self):
        return self.is_user_defined

    def allow_address_edits(self):
        return self.is_user_defined

    def is_valid_input(self):
        # if self.is_user_defined and self.current_fallthrough_addr is None:
        #     inst = self.program.get_listing().get_instruction_containing(self.current_addr)
        #     if inst.fall_through() is not None:
        #         return False
        return True

    def get_message(self):
        msg = self.message
        self.message = ""
        return msg

    def get_instruction_representation(self):
        inst = self.program.get_listing().get_instruction_containing(self.current_addr)
        if inst is None:
            return "No instruction found"
        else:
            return self.cu_format.get_representation_string(inst)

    def execute(self):
        self.message = ""
        inst = self.program.get_listing().get_instruction_containing(self.current_addr)
        ft_addr = inst.fall_through()
        if ft_addr is None or not ft_addr.equals(self.current_fallthrough_addr):
            self.executing_command = True
            cmd = SetFallThroughCmd(inst.min_address(), self.current_fallthrough_addr)
            self.tool.execute(cmd, self.program)
            self.message = "Updated Fallthrough address"
            self.executing_command = False
            if self.default_fallthrough_addr is not None and \
               ft_addr.equals(self.current_fallthrough_addr):
                self.is_default = True
                self.is_user_defined = False
        else:
            self.message = "No changes were made"
        self.listener.state_changed(None)
        return True

    def auto_override(self, view):
        cmd = CompoundCmd("Auto-Override")
        iter = view.get_address_ranges()
        while iter.has_next():
            override(iter.next(), cmd)
        if cmd.size() > 0:
            if not self.tool.execute(cmd, self.program):
                self.tool.set_status_info(cmd.status_msg())
        return

    def clear_override(self, view):
        cmd = CompoundCmd("Clear FallThroughs")
        it = self.program.get_listing().get_instructions(view, True)
        while it.has_next():
            inst = it.next()
            if inst.is_fall_through_overridden():
                cmd.add(ClearFallThroughCmd(inst.min_address()))
        if cmd.size() > 0:
            self.tool.execute(cmd, self.program)

    def dispose(self):
        self.program = None
        self.tool = None
        self.listener = None

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value


class BrowserCodeUnitFormat:
    def __init__(self, tool):
        pass

    def get_representation_string(self, inst):
        # TO DO: implement this method
        pass


# Usage example:

tool = PluginTool()
program = Program()
address = Address()

model = FallThroughModel(tool, program, address)
```

Please note that the translation is not a direct conversion from Java to Python. Some parts of the code have been modified or simplified according to Python's syntax and best practices.