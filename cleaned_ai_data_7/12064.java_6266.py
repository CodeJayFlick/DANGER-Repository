class ProgramRegisterContextDB:
    def __init__(self, db_handle: object, error_handler: object, language: object,
                 compiler_spec: object, address_map: object, lock: object, open_mode: int,
                 code_manager: object, task_monitor: object):
        super().__init__(language)
        self.addr_map = address_map
        self.db_handle = db_handle
        self.error_handler = error_handler
        self.lock = lock

    def initialize_default_values(self, language: object, compiler_spec: object) -> None:
        default_register_value_map.clear()
        lang.apply_context_settings(self)
        if compiler_spec is not None:
            compiler_spec.apply_context_settings(self)

    @property
    def register_value_map(self):
        return self._register_value_map

    @register_value_map.setter
    def register_value_map(self, value: object) -> None:
        self._register_value_map = value

    def set_program(self, program: object) -> None:
        self.program = program

    def move_address_range(self, from_addr: Address, to_addr: Address, length: int,
                            task_monitor: TaskMonitor):
        super().move_address_range(from_addr, to_addr, length, task_monitor)

    def invalidate_cache(self, all: bool) -> None:
        self.invalidate_read_cache()

    @property
    def program_ready(self):
        return self._program_ready

    @program_ready.setter
    def program_ready(self, value: int) -> None:
        if value == 1:
            super().program_ready(0)
        else:
            raise Exception("Unexpected context error during upgrade")

    def set_register_value(self, start: Address, end: Address, register_value: object):
        self.lock.acquire()
        try:
            check_context_write(register_value.get_register(), start, end)
            if not changing and restore:
                changing = True
            super().set_register_value(start, end, register_value)
            if program is not None:
                program.set_register_values_changed(register_value.get_register(),
                                                     start,
                                                     end)
        finally:
            self.lock.release()

    def set_language(self, translator: object, compiler_spec: CompilerSpec,
                     address_set_view: AddressSetView, task_monitor: TaskMonitor) -> None:
        if translator is not None:
            new_language = translator.get_new_language()
            for register in sorted(language.get_registers(), key=lambda r: r.bit_length(),
                                     reverse=True):
                monitor.check_cancelled()
                if not register.is_base_register():
                    continue
                store = self.register_value_map.get(register)
                if store is not None and clear_context:
                    Msg.warn(self, f"WARNING! Discarding all context for register {register.name}")
                    store.clear_all()
            init(new_language)

    def fill_in_context_gaps(self, ctx_reg: Register, gap_value: object,
                              address_set_view: AddressSetView) -> None:
        area = new_address_set(address_set_view)
        store = self.register_value_map.get(ctx_reg)
        if store is not None:
            for range in store.address_range_iterator():
                area.delete(range)
        ranges = area.address_ranges()
        while ranges.has_next():
            start, end = ranges.next().get_min_address(), ranges.next().get_max_address()
            try:
                set_register_value(start, end, gap_value)
            except ContextChangeException as e:
                raise Exception("Unexpected context error during language upgrade", e)

    def flush_processor_context_write_cache(self) -> None:
        self.lock.acquire()
        try:
            super().flush_processor_context_write_cache()
        finally:
            self.lock.release()

    def invalidate_processor_context_write_cache(self):
        self.lock.acquire()
        try:
            super().invalidate_processor_context_write_cache()
        finally:
            self.lock.release()

    @property
    def register_value_address_ranges(self) -> object:
        return self._register_value_address_ranges

    @register_value_address_ranges.setter
    def register_value_address_ranges(self, value: object):
        self._register_value_address_ranges = value

    def get_register_value_range_containing(self, register: Register,
                                             address: Address) -> object:
        self.lock.acquire()
        try:
            return super().get_register_value_range_containing(register, address)
        finally:
            self.lock.release()

    @property
    def default_register_value_map(self):
        return self._default_register_value_map

    @default_register_value_map.setter
    def default_register_value_map(self, value: object) -> None:
        self._default_register_value_map = value

    def set_default_value(self, register_value: RegisterValue,
                           start: Address, end: Address) -> None:
        self.lock.acquire()
        try:
            super().set_default_value(register_value, start, end)
        finally:
            self.lock.release()

    @property
    def non_default_register_value_map(self):
        return self._non_default_register_value_map

    @non_default_register_value_map.setter
    def non_default_register_value_map(self, value: object) -> None:
        self._non_default_register_value_map = value

    def get_non_default_value(self, register: Register,
                               address: Address) -> object:
        self.lock.acquire()
        try:
            return super().get_non_default_value(register, address)
        finally:
            self.lock.release()

class OldProgramContextDB:
    @staticmethod
    def old_context_data_exists(db_handle: object):
        for table in db_handle.get_tables():
            if table.name.startswith(DatabaseRangeMapAdapter.CONTEXT_TABLE_PREFIX):
                return True
        return False

    @staticmethod
    def remove_old_context_data(db_handle: object) -> None:
        try:
            # code to remove old context data goes here
            pass
        except IOException as e:
            error_handler.db_error(e)

class AddressSetView:
    def __init__(self):
        self.address_set = new_address_set()

    @property
    def address_set(self):
        return self._address_set

    @address_set.setter
    def address_set(self, value: object) -> None:
        self._address_set = value

class AddressSet:
    def __init__(self, address_set_view: AddressSetView):
        self.address_ranges = new_address_range_iterator(address_set_view)

    @property
    def address_ranges(self):
        return self._address_ranges

    @address_ranges.setter
    def address_ranges(self, value: object) -> None:
        self._address_ranges = value

class TaskMonitor:
    def __init__(self):
        pass

    def check_cancelled(self) -> None:
        # code to check if task is cancelled goes here
        pass

    @property
    def monitor(self):
        return self._monitor

    @monitor.setter
    def monitor(self, value: object) -> None:
        self._monitor = value

class CompilerSpec:
    def __init__(self):
        pass

    def apply_context_settings(self, program_register_context_db: ProgramRegisterContextDB) -> None:
        # code to apply context settings goes here
        pass

class LanguageTranslator:
    def __init__(self):
        pass

    @property
    def new_language(self):
        return self._new_language

    @new_language.setter
    def new_language(self, value: object) -> None:
        self._new_language = value

    def get_new_register_value(self, register_value: RegisterValue) -> object:
        # code to translate register values goes here
        pass

class AddressRangeMapAdapter:
    @staticmethod
    def CONTEXT_TABLE_PREFIX():
        return "context_"

    @staticmethod
    def NAME_PREFIX():
        return "_name_prefix"
