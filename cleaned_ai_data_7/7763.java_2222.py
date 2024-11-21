class CreateEHFuncInfoBackgroundCmd:
    def __init__(self, address):
        self.model = None
        super().__init__('EHFunctionInfoModel.DATA_ TYPE_NAME', address)

    def create_model(self, program):
        if not self.model:
            self.model = EHFunctionInfoModel(program, self.get_data_address(), self.validation_options)
        return self.model

    @property
    def validation_options(self):
        # This property should be implemented based on the provided Java code.
        pass

    @property
    def apply_options(self):
        # This property should be implemented based on the provided Java code.
        pass

    def create_associated_data(self) -> bool:
        if self.model is None:
            return False  # Shouldn't happen. create...() is only called if model is valid.

        unwind_map_success = self.create_unwind_map_entries()
        try_block_map_success = self.create_try_block_map_entries()
        ip_to_state_map_success = self.create_ip_to_state_map_entries()
        type_list_success = self.create_estype_list_entries()

        return all([unwind_map_success, try_block_map_success, ip_to_state_map_success, type_list_success])

    def create_unwind_map_entries(self) -> bool:
        if not self.model:
            return False  # Shouldn't happen. create...() is only called if model is valid.

        comp_address = None
        unwind_map_address = None
        unwind_count = 0

        try:
            comp_address = self.model.get_component_address_of_unwind_map_address()
            unwind_map_address = self.model.get_unwind_map_address()
            unwind_count = self.model.get_unwind_count()

        except InvalidDataTypeException as e:
            raise AssertException(e) from None

        if not (unwind_map_address and unwind_count > 0):
            return True  # No unwind info to create.

        try_block_model = self.model.get_unwind_model()
        try_block_model.validate()  # Shouldn't happen. create...() is only called if model is valid.
        CreateEHUnwindMapBackgroundCmd(cmd=self, apply_options=self.apply_options).apply_to(self.model.get_program())

    def create_try_block_map_entries(self) -> bool:
        comp_address = None
        try_block_map_address = None
        try_block_count = 0

        try:
            comp_address = self.model.get_component_address_of_try_block_map_address()
            try_block_map_address = self.model.get_try_block_map_address()
            try_block_count = self.model.get_try_block_count()

        except InvalidDataTypeException as e:
            raise AssertException(e) from None

        if not (try_block_map_address and try_block_count > 0):
            return True  # No try block info to create.

        try_block_model = self.model.get_try_block_model()
        try_block_model.validate()  # Shouldn't happen. create...() is only called if model is valid.
        CreateEHTryBlockMapBackgroundCmd(cmd=self, apply_options=self.apply_options).apply_to(self.model.get_program())

    def create_ip_to_state_map_entries(self) -> bool:
        comp_address = None
        ip_to_state_map_address = None

        try:
            comp_address = self.model.get_component_address_of_ip_to_state_map_address()
            ip_to_state_map_address = self.model.get_ip_to_state_map_address()

        except InvalidDataTypeException as e:
            raise AssertException(e) from None

        if not (ip_to_state_map_address):
            return True  # No IP to state info to create.

        try_block_model = self.model.get_ip_to_state_model()
        try_block_model.validate()  # Shouldn't happen. create...() is only called if model is valid.
        CreateEHIPToStateMapBackgroundCmd(cmd=self, apply_options=self.apply_options).apply_to(self.model.get_program())

    def create_estype_list_entries(self) -> bool:
        comp_address = None
        es_type_list_address = None

        try:
            comp_address = self.model.get_component_address_of_es_type_list_address()
            es_type_list_address = self.model.get_es_type_list_address()

        except InvalidDataTypeException as e:
            raise AssertException(e) from None

        if not (es_type_list_address):
            return True  # No ES type list to create.

        try_block_model = self.model.get_es_type_list_model()
        try_block_model.validate()  # Shouldn't happen. create...() is only called if model is valid.
        CreateEHESTypeListBackgroundCmd(cmd=self, apply_options=self.apply_options).apply_to(self.model.get_program())

    def handle_error_message(self):
        pass

class EHFunctionInfoModel:
    @property
    def data_type_name(self):
        # This property should be implemented based on the provided Java code.
        pass

    @property
    def program(self):
        # This property should be implemented based on the provided Java code.
        pass

    @property
    def component_address_of_unwind_map_address(self):
        # This property should be implemented based on the provided Java code.
        pass

    @property
    def unwind_count(self):
        # This property should be implemented based on the provided Java code.
        pass

class CreateEHUnwindMapBackgroundCmd:
    def __init__(self, cmd, apply_options):
        self.cmd = cmd
        self.apply_options = apply_options

    def apply_to(self, program):
        return True  # Shouldn't happen. create...() is only called if model is valid.

# This class should be implemented based on the provided Java code.
class CreateEHTryBlockMapBackgroundCmd:
    pass

# This class should be implemented based on the provided Java code.
class CreateEHIPToStateMapBackgroundCmd:
    pass

# This class should be implemented based on the provided Java code.
class CreateEHESTypeListBackgroundCmd:
    pass
