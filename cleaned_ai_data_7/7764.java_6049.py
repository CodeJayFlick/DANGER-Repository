class CreateEHIPToStateMapBackgroundCmd:
    def __init__(self, address: int, count: int):
        self.address = address
        self.count = count

    def create_model(self, program) -> 'CreateEHIPToStateModel':
        if not hasattr(self, 'model'):
            model = CreateEHIPToStateModel(program=program, count=self.count, data_address=self.address)
            setattr(self, 'model', model)
        return getattr(self, 'model')

    def create_associated_data(self) -> bool:
        try:
            return self.create_ip_refs()
        except CancelledException as e:
            raise

    def create_ip_refs(self) -> bool:
        # NOTE: Current components which utilize ibo32 get a reference created
        # automatically by the CodeManager.  Components which produce Scalar values
        # (e.g., ULONG) are ignored.
        return True

    def create_markup(self) -> bool:
        try:
            return True  # No markup.
        except CancelledException as e:
            raise


class CreateEHIPToStateMapBackgroundCmdWithValidationAndApplyOptions(CreateEHIPToStateMapBackgroundCmd):
    def __init__(self, address: int, count: int, validation_options: 'DataValidationOptions', apply_options: 'DataApplyOptions'):
        super().__init__(address=address, count=count)
        self.validation_options = validation_options
        self.apply_options = apply_options


class CreateEHIPToStateMapBackgroundCmdWithModel(CreateEHIPToStateMapBackgroundCmd):
    def __init__(self, ip_to_state_model: 'CreateEHIPToStateModel', apply_options: 'DataApplyOptions'):
        super().__init__(ip_to_state_model=ip_to_state_model, apply_options=apply_options)
