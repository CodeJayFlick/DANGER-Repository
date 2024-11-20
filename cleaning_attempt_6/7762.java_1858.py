class CreateEHESTypeListBackgroundCmd:
    def __init__(self, address):
        self.address = address

    def create_model(self, program):
        if not hasattr(self, 'model'):
            model = EHESTypeListModel(program, self.address)
            setattr(self, 'model', model)
        return getattr(self, 'model')

    def apply_to_program(self, program):
        try:
            catch_handler_count = self.model.get_handler_type_count()
            handler_type_map_address = self.model.get_handler_type_map_address()
            component_address = self.model.get_component_address_of_handler_type_map_address()

            if not (handler_type_map_address and catch_handler_count > 0):
                return True

            monitor.check_cancelled()

            catch_handler_model = self.model.get_catch_handler_model()
            try:
                catch_handler_model.validate()
            except InvalidDataTypeException as e1:
                handle_error(program, catch_handler_model.name, handler_type_map_address,
                              component_address, str(e1))
                return False

            cmd = CreateEHCatchHandlerMapBackgroundCmd(catch_handler_model)
            return cmd.apply_to_program(program)

        except CancelledException:
            return False
        except InvalidDataTypeException as e:
            raise AssertException(str(e))

    def create_associated_data(self):
        try:
            if self.create_catch_handler_map_entries():
                return True
            else:
                return False

        except CancelledException:
            return False


class EHESTypeListModel:
    DATA_TYPE_NAME = 'ESTypeList'

    def __init__(self, program, address, validation_options=None):
        self.program = program
        self.address = address
        self.validation_options = validation_options

    @property
    def data_type_name(self):
        return self.__class__.DATA_TYPE_NAME


def handle_error(program, catch_handler_model_name, handler_type_map_address,
                 component_address, error_message):
    print(f"Error creating {catch_handler_model_name} at address "
          f"{handler_type_map_address}. Component address: {component_address}")
    raise Exception(error_message)


# Usage example:
if __name__ == "__main__":
    program = Program()  # Replace with your actual program
    create_cmd = CreateEHESTypeListBackgroundCmd(program.getAddress())
    try:
        result = create_cmd.apply_to_program(program)
        print(f"Result: {result}")
    except Exception as e:
        print(str(e))
