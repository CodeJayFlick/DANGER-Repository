class FunctionParameterNameFieldLocation:
    def __init__(self, program=None, location_addr=None, function_addr=None,
                 char_offset=0, signature="", parameter=None):
        super().__init__(program, location_addr, function_addr, char_offset, signature, parameter)
        self.parameter_name = parameter.name if parameter else ""

    def get_parameter_name(self):
        return self.parameter_name

class SaveState:
    pass

def save_state(obj, instance):
    obj.put_string("_FUNCTION_PARAMETER_NAME", instance.parameter_name)

def restore_state(program, obj, instance):
    super().restore_state(program, obj)
    instance.parameter_name = obj.get_string("_FUNCTION_PARAMETER_NAME", None)


# Test the class
program = "Program"
location_addr = 1
function_addr = 2
char_offset = 3
signature = "Signature"
parameter = {"name": "Parameter"}

fpnfl = FunctionParameterNameFieldLocation(program, location_addr, function_addr,
                                            char_offset, signature, parameter)
print(fpnfl.get_parameter_name())

# Test the save and restore methods
save_state_obj = SaveState()
restore_state_obj = SaveState()

save_state(save_state_obj, fpnfl)

fpnfl_restored = FunctionParameterNameFieldLocation(program, location_addr, function_addr,
                                                      char_offset, signature, parameter)
restore_state(program, restore_state_obj, fpnfl_restored)

print(fpnfl_restored.get_parameter_name())
