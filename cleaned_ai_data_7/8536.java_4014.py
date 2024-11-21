from collections import defaultdict, deque

class ComplexTypeApplierMapper:
    def __init__(self, applicator):
        self.applicator = applicator
        self.composite_appliers_queue_by_symbol_path = defaultdict(deque)
        self.enum_appliers_queue_by_symbol_path = defaultdict(deque)

    def map_appliers(self, monitor):
        type_program_interface = self.applicator.get_pdb().get_type_program_interface()
        if not type_program_interface:
            return

        index_limit = type_program_interface.get_type_index_max_exclusive()
        index_number = type_program_interface.get_type_index_min()

        while index_number < index_limit:
            monitor.check_cancelled()
            applier = self.applicator.get_type_applier(RecordNumber.type_record_number(index_number))
            if isinstance(applier, CompositeTypeApplier):
                self.map_complex_applier_two_way_by_symbol_path(self.composite_appliers_queue_by_symbol_path, applier)
            elif isinstance(applier, EnumTypeApplier):
                self.map_complex_applier_two_way_by_symbol_path(self.enum_appliers_queue_by_symbol_path, applier)

            index_number += 1
            monitor.increment_progress(1)

    def map_complex_applier_two_way_by_symbol_path(self, applier_queue_by_symbol_path, complex_applier):
        symbol_path = complex_applier.get_symbol_path()
        if not symbol_path:
            return

        appliers = applier_queue_by_symbol_path[symbol_path]
        if not appliers:
            appliers.append(complex_applier)
        elif (appliers[0].is_forward_reference() == complex_applier.is_forward_reference()):
            appliers.append(complex_applier)
        else:
            if complex_applier.is_forward_reference():
                definition_applier = appliers.popleft()
                definition_applier.set_forward_reference_applier(complex_applier)
                complex_applier.set_definition_applier(definition_applier)
            else:
                forward_reference_applier = appliers.popleft()
                forward_reference_applier.set_definition_applier(complex_applier)
                complex_applier.set_forward_reference_applier(forward_reference_applier)

        if not appliers:
            del applier_queue_by_symbol_path[symbol_path]

class CompositeTypeApplier:
    def __init__(self, symbol_path):
        self.symbol_path = symbol_path

    @property
    def is_forward_reference(self):
        return False  # implement this method as needed

    def get_symbol_path(self):
        return self.symbol_path


class EnumTypeApplier(CompositeTypeApplier):
    pass
