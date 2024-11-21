class NextPreviousNonFunctionAction:
    def __init__(self, tool, owner, sub_group):
        super().__init__(tool, "Next Non-Function", owner, sub_group)

    @property
    def icon(self):
        return ResourceManager.load_image("images/notF.gif")

    @property
    def key_stroke(self):
        return KeyStroke(vk_n=KeyEvent.VK_N,
                         input_event_mask=(InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK))

    @property
    def navigation_type_name(self):
        return "Instruction Not In a Function"

    def get_next_address(self, monitor, program, address):
        function = program.get_listing().get_function_containing(address)
        if not function:
            function = self._next_function(program, address, True)
        if not function:
            return None
        return self._find_next_instruction_address_not_in_function(monitor, program, function.entry_point(), True)

    def get_previous_address(self, monitor, program, address):
        function = program.get_listing().get_function_containing(address)
        if not function:
            function = self._next_function(program, address, False)
        if not function:
            return None
        return self._find_next_instruction_address_not_in_function(monitor, program, function.entry_point(), False)

    def _find_next_instruction_address_not_in_function(self, monitor, program, address, is_forward):
        function = program.get_listing().get_function_containing(address)
        body = function.body if function else None
        it = program.get_listing().instructions(address, is_forward)
        while it.has_next():
            instruction = it.next()
            instruction_address = instruction.min_address
            if not (body and body.contains(instruction_address)):
                return instruction_address
        return None

    def _next_function(self, program, address, forward):
        function_iterator = program.get_listing().functions(address, forward)
        if not function_iterator.has_next():
            return None
        return function_iterator.next()

    def goto_address(self, service, navigatable, address):
        service.go_to(navigatable, address)

class ResourceManager:
    @staticmethod
    def load_image(image_name):
        # Load the image from resources or database.
        pass

class KeyStroke:
    def __init__(self, vk_n=0, input_event_mask=None):
        self.vk_n = vk_n
        self.input_event_mask = input_event_mask

class InstructionIterator:
    @property
    def has_next(self):
        # Check if there are more instructions.
        pass

    def next(self):
        # Return the next instruction.
        pass

class AddressSetView:
    @property
    def contains(self, address):
        # Check if the given address is in this set view.
        pass

class Instruction:
    @property
    def min_address(self):
        # Get the minimum address of this instruction.
        pass

class FunctionIterator:
    @property
    def has_next(self):
        # Check if there are more functions.
        pass

    def next(self):
        # Return the next function.
        pass

class Program:
    def get_listing(self):
        # Get the program listing.
        pass

    def instructions(self, address, is_forward):
        # Iterate over the instructions starting from the given address in the specified direction (forward or backward).
        pass

    def functions(self, address, forward):
        # Iterate over the functions containing the given address and going in the specified direction (forward or backward).
        pass
