class HashMatch:
    def __init__(self, function_record: 'ghidra.feature.fid.db.FunctionRecord',
                 primary_function_code_unit_score: float,
                 primary_function_match_mode: 'ghidra.feature.fid.plugin.HashLookupListMode',
                 child_function_code_unit_score: float,
                 parent_function_code_unit_score: float):
        self.function_record = function_record
        self.primary_function_code_unit_score = primary_function_code_unit_score
        self.primary_function_match_mode = primary_function_match_mode
        self.child_function_code_unit_score = child_function_code_unit_score
        self.parent_function_code_unit_score = parent_function_code_unit_score

    def get_function_record(self):
        return self.function_record

    def get_primary_function_code_unit_score(self):
        return self.primary_function_code_unit_score

    def get_primary_function_match_mode(self):
        return self.primary_function_match_mode

    def get_child_function_code_unit_score(self):
        return self.child_function_code_unit_score

    def get_parent_function_code_unit_score(self):
        return self.parent_function_code_unit_score

    def __str__(self):
        overall_score = self.get_primary_function_code_unit_score() + \
                         self.get_child_function_code_unit_score() + \
                         self.get_parent_function_code_unit_score()
        return f"{overall_score:.1f} - {self.primary_function_code_unit_score:.1f} ({self.primary_function_match_mode})/{self.child_function_code_unit_score:.1f}/{self.parent_function_code_unit_score:.1f} {self.function_record.__str__()}"
