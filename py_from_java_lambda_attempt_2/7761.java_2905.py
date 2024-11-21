Here is a translation of the provided Java code into equivalent Python:

```Python
class CreateEHCatchHandlerMapBackgroundCmd:
    def __init__(self, address: int, count: int):
        self.model = None
        super().__init__("EH_CATCH_HANDLER_MAP", address, count)

    def create_model(self, program) -> 'CreateEHCatchHandlerModel':
        if not self.model:
            self.model = CreateEHCatchHandlerModel(program, count, self.get_data_address())
        return self.model

    @property
    def model(self):
        return self._model

    @model.setter
    def model(self, value: 'CreateEHCatchHandlerModel'):
        self._model = value

class EHCatchHandlerMapBackgroundCmd:
    def __init__(self, address: int, count: int, validation_options=None, apply_options=None):
        super().__init__("EH_CATCH_HANDLER_MAP", address, count, validation_options, apply_options)

    @property
    def model(self):
        return self._model

    @model.setter
    def model(self, value: 'CreateEHCatchHandlerModel'):
        self._model = value

class CreateTypeDescriptors:
    def __init__(self, program: Program, monitor=None):
        self.monitor = monitor if monitor else CancelledExceptionMonitor()
        self.result = True

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value: bool):
        self._result = value

    def create_type_descriptors(self) -> bool:
        for catch_handler_ordinal in range(count):
            if not self.monitor.check_cancelled():
                break
            comp_address = None
            type_descriptor_address = None
            try:
                comp_address = model.get_component_address_of_type_descriptor_address(catch_handler_ordinal)
                type_descriptor_address = model.get_type_descriptor_address(catch_handler_ordinal)
            except InvalidDataTypeException as e:
                raise AssertException(e)

            if not type_descriptor_address:
                continue

            type_descriptor_model = None
            try:
                type_descriptor_model = model.get_type_descriptor_model(catch_handler_ordinal)
            except InvalidDataTypeException as e:
                raise AssertException(e)

            try:
                type_descriptor_model.validate()
            except InvalidDataTypeException as e1:
                handle_error_message(program, type_descriptor_model.name, type_descriptor_address, comp_address, e1)
                self.result = False
                continue

            int type_descriptor_count = type_descriptor_model.get_count()

            if not type_descriptor_count:
                continue

            CreateTypeDescriptorBackgroundCmd(cmd).apply_to(program, monitor)

        return self.result


class Program:
    def __init__(self):
        pass

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value: 'Program'):
        self._program = value

class EHCatchHandlerModel:
    def __init__(self, program: Program, count: int, address: Address, validation_options=None):
        super().__init__("EH_CATCH_HANDLER_MAP", program, count, address)

    @property
    def model(self):
        return self._model

    @model.setter
    def model(self, value: 'EHCatchHandlerModel'):
        self._model = value


class CancelledExceptionMonitor:
    pass