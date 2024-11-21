from typing import List, Tuple

class VariableStorageConflicts:
    def __init__(self, variables_list1: List['Variable'], 
                 variables_list2: List['Variable'], ignore_param_to_param_conflicts: bool,
                 monitor):
        self.overlapping_variables = []
        self.ignore_param_to_param_conflicts = ignore_param_to_param_conflicts
        self.non_overlapping_variables1 = []
        self.non_overlapping_variables2 = []

    def get_overlapping_variables(self, first_use_offset: int, variables_list1: List['Variable'],
                                   set1: 'AddressSet', overlap_list1: List['Variable'], 
                                   variables_list2: List['Variable'], set2: 'AddressSet',
                                   overlap_list2: List['Variable'], monitor):
        expanded = True
        while expanded:
            expanded = False
            for i in range(len(variables_list2)):
                if find_overlaps(first_use_offset, variables_list2, i, overlap_list2,
                                set2, self.non_overlapping_variables2, set1) or \
                   find_overlaps(first_use_offset, variables_list1, 0, overlap_list1,
                                set1, self.non_overlapping_variables1, set2):
                    expanded = True
            for var in variables_list1:
                if monitor.check_cancelled():
                    return False
                storage = var.get_variable_storage()
                if storage.intersects(set1) or storage.intersects(set2):
                    overlap_list1.append(var)
                    self.non_overlapping_variables1.remove(var)

    def find_overlaps(self, first_use_offset: int, variables: List['Variable'], index: int,
                      overlap_list: List['Variable'], set: 'AddressSet', non_overlap_list: List['Variable'],
                      intersect_set: 'AddressSetView'):
        var = variables[index]
        if not (var.get_first_use_offset() == first_use_offset and
                (not self.param_only_address_sets or 
                 not isinstance(var, Parameter) or 
                 self.ignore_param_to_param_conflicts)):
            return False

        storage = var.get_variable_storage()
        if storage.intersects(intersect_set):
            variables[index] = None  # avoid concurrent modification and mark as consumed
            overlap_list.append(var)
            non_overlap_list.remove(var)

    def add_all_parameters(self, variables: List['Variable'], overlap_list: List['Variable'],
                            set: 'AddressSet', non_overlap_list: List['Variable']):
        parameters_added = False
        for i in range(len(variables)):
            if isinstance(variables[i], Parameter):
                variables[i] = None  # avoid concurrent modification and mark as consumed
                overlap_list.append(variables[i])
                parameters_added = True

    def get_overlapping_variables(self) -> List[Tuple[List['Variable'], List['Variable']]]:
        return self.overlapping_variables

    def has_overlap_conflict(self):
        return len(self.overlapping_variables) > 0

    def has_parameter_conflict(self):
        return self.parameters_conflicted

    def is_conflicted(self, var1: 'Variable', var2: 'Variable'):
        for pair in self.overlapping_variables:
            if var1 and contains_variable(pair[0], var1):
                return True
            if var2 and contains_variable(pair[1], var2):
                return True
        return False

    def contains_variable(self, list: List['Variable'], var: 'Variable'):
        for v in list:
            if var == v:
                return True
        return False

class Variable:
    pass  # abstract class; implement methods as needed

class AddressSetView:
    pass  # abstract class; implement methods as needed

# usage example:

var_storage_conflicts = VariableStorageConflicts(variables_list1, variables_list2,
                                                   ignore_param_to_param_conflicts, monitor)
print(var_storage_conflicts.get_overlapping_variables())
