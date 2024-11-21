Here is a translation of your Java code into equivalent Python:

```Python
import hashlib
from collections import defaultdict

class StringParameterPropagator:
    def __init__(self):
        self.decomplib = None
        self.func_info_map = {}
        self.string_location_set = set()
        self.referring_func_location_set = set()

    @staticmethod
    def collect_string_data_reference_locations(data_item_location_set, referring_func_location_set):
        data_iter = current_program.get_listing().get_defined_data(True)
        while data_iter.has_next():
            data = data_iter.next()
            if isinstance(data.get_data_type(), (str, unicode)):
                string_location_set.add(data.get_address())
                reference_iterator = current_program.get_reference_manager().get_references_to(data.get_address())
                for ref in reference_iterator:
                    func = current_program.get_function_manager().get_function_containing(ref.get_from_address())
                    referring_func_location_set.add(func.get_entry_point())

    @staticmethod
    def collect_data_refence_locations(data_item_location_set, referring_func_location_set):
        count = 0
        reference_iter = current_program.get_reference_manager().get_reference_iterator(current_program.get_min_address())
        while reference_iter.has_next():
            ref = reference_iter.next()
            if not ref.is_flow() and ref.is_memory_reference():
                data_item_location_set.add(ref.get_to_address())
                func = current_program.get_function_manager().get_function_containing(ref.get_from_address())
                referring_func_location_set.add(func.get_entry_point())

    @staticmethod
    def mark_string_param(const_use, ref_addr, entry, param_index, num_params):
        cur_val = const_use[entry]
        if not cur_val:
            cur_val = FuncInfo()
            const_use[entry] = cur_val

        cur_val.set_num_params_seen(num_params)
        cur_val.set_param_seen(param_index)

    @staticmethod
    def check_params(func, dt, param_index, min_params, could_be_vararg):
        if not func or not dt:
            return False

        initial_convention = func.get_calling_convention()
        convention = None
        for i in range(min_params + 1):
            storage = convention.get_arg_location(i - 1, func.get_parameters(), dt)
            if storage.is_unassigned_storage():
                break

    @staticmethod
    def fixup_params(f, min_params, could_be_vararg):
        if not f:
            return

        for i in range(min_params + 1):
            param = f.add_parameter(i - 1)

class FuncInfo:
    def __init__(self):
        self.min_param_seen = 256
        self.max_param_seen = 0
        self.params_noted = set()
        self.dt = None

    @staticmethod
    def get_min_params_seen(self):
        return self.min_param_seen

    @staticmethod
    def get_max_params_seen(self):
        return self.max_param_seen

class Address:
    pass

class Program:
    def __init__(self, min_address):
        self.min_address = min_address

    def get_listing(self):
        # todo: implement this method
        pass

    def get_function_manager(self):
        # todo: implement this method
        pass

    def get_reference_manager(self):
        # todo: implement this method
        pass

class Function:
    def __init__(self, entry_point):
        self.entry_point = entry_point

    @staticmethod
    def get_calling_convention(self):
        return None  # todo: implement this method

    @staticmethod
    def add_parameter(self, param_index):
        # todo: implement this method
        pass

class PcodeOp:
    pass

class Varnode:
    pass

def apply_def_use_list(value, local_def_use_list):
    if not local_def_use_list:
        return value  # todo: handle exceptions here
```

Please note that the above Python code is a direct translation of your Java code and may require some modifications to work correctly.