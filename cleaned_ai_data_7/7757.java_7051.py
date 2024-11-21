class AbstractCreateDataBackgroundCmd:
    def __init__(self, model: 'AbstractCreateDataTypeModel', apply_options):
        super().__init__("Create " + str(model) + " Data", True, True, True)
        self.model = model
        self.name = model.get_name()
        self.address = model.get_address()
        self.count = model.get_count()
        self.validation_options = model.get_validation_options()
        self.apply_options = apply_options

    def do_apply_to(self, obj: 'DomainObject', task_monitor):
        try:
            if not isinstance(obj, Program):
                message = "Can only apply a {} data type to a program.".format(self.name)
                handle_error(message)
                return False
            return self._do_apply_to((obj), task_monitor)

        except CancelledException as e:
            set_status_msg("User cancelled {}".format(self.get_name()))
            # FUTURE: Throw this exception instead of catching it, once BackgroundCommand throws it.
            return False

    def create_model(self, program):
        pass  # Abstract method to be implemented by subclasses.

    def get_data_type(self) -> 'DataType':
        if not self.model.is_initialized():
            raise ValueError("Model isn't initialized")
        return self.model.get_data_type()

    def do_create_data(self) -> bool:
        try:
            memory = program.memory
            data_at = listing.data_at(self.address)
            dt = get_data_type()
            if dt is None:
                raise CodeUnitInsertionException(
                    "Unable to get data type from model, {}".format(self.model.name))
            if not memory.get_loaded_and_initialized_address_set().contains(self.address):
                message = "Can't create an {} @ {} which isn't in loaded and initialized memory for {}".format(dt.name,
                                                                                                               self.address,
                                                                                                               program.name)
                raise CodeUnitInsertionException(message)

            # When creating data, this will create an array with count number of elements
            # of the model's data type if the data type obtained from the model hasn't
            # already done so.
            if not self.model.is_data_type_already_based_on_count() and self.count > 1:
                dt = ArrayDataType(dt, self.count, dt.length(), program.data_type_manager)

            task_monitor.check_cancelled()

            # Is the data type already applied at the address?
            if matching_data_exists(dt, program, self.address):
                return False

            monitor.check_cancelled()
            DataUtilities.create_data(program, self.address, dt, dt.length(), False,
                                       get_clear_data_mode())

            return True
        except (CancelledException, CodeUnitInsertionException) as e:
            handle_error("Couldn't create {} data @ {}".format(self.name, self.address), e)
            return False

    def matching_data_exists(self, dt: 'DataType', program: 'Program', start_address):
        listing = program.listing
        data_at = listing.data_at(start_address)
        if data_at is not None and data_at.get_data_type() == dt:
            return True  # Already set to the desired data type.
        return False

    def create_markup(self) -> bool:
        pass  # Abstract method to be implemented by subclasses.

    def create_associated_data(self):
        pass  # Abstract method to be implemented by subclasses.

    @staticmethod
    def handle_error(message, e=None):
        if e is not None and e.message is not None:
            message += " {}".format(e.message)
        Msg.error(AbstractCreateDataBackgroundCmd, message)

    @staticmethod
    def get_clear_data_mode():
        return ClearDataMode.CLEAR_ALL_CONFLICT_DATA

class Program:  # This class should be implemented by subclasses.
    pass


def main():
    model = AbstractCreateDataTypeModel()
    apply_options = DataApplyOptions()

    cmd = AbstractCreateDataBackgroundCmd(model, apply_options)
    program = Program()  # Should be replaced with the actual implementation.

    try:
        result = cmd.do_apply_to(program, task_monitor)  # Replace with your own code.
    except CancelledException as e:
        print("User cancelled command.")
