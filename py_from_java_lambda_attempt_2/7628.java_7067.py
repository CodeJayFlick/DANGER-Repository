Here is the translation of the Java code into Python:

```Python
class FidProgramSeeker:
    def __init__(self, fid_query_service, program, hasher, short_hash_code_unit_length,
                 medium_hash_code_unit_length_limit, score_threshold):
        self.fid_query_service = fid_query_service
        self.program = program
        self.score_threshold = score_threshold
        self.medium_hash_code_unit_length_limit = medium_hash_code_unit_length_limit

    def get_children(self, function, follow_thunks):
        func_list = []
        already_done = set()
        reference_manager = self.program.get_reference_manager()

        for address in reference_manager.get_references_from(function.get_entry_point()):
            if address not in already_done:
                child = self.program.get_function_manager().get_function_containing(address)
                if child is not None and (not follow_thunks or not child.is_thunk()):
                    func_list.append(child)
                    already_done.add(address)

        return func_list

    def add_children(self, family, function, monitor):
        children = self.get_children(function, True)
        for relation in children:
            try:
                hash = self.cache_factory.get(relation)
                if hash is not None:
                    family.add_child(hash)
            except CancelledException as e:
                print(f"Cancelled: {e}")

    def get_parents(self, function, follow_thunks):
        func_list = []
        already_done = set()
        reference_manager = self.program.get_reference_manager()

        for address in range(function.get_entry_point(), -1, -1):
            if not already_done.contains(address):
                parent = self.program.get_function_manager().get_function_containing(address)
                if parent is not None and (not follow_thunks or not parent.is_thunk()):
                    func_list.append(parent)
                    already_done.add(address)

        return func_list

    def add_parents(self, family, function, monitor):
        parents = self.get_parents(function, True)
        for relation in parents:
            try:
                hash = self.cache_factory.get(relation)
                if hash is not None:
                    family.add_parent(hash)
            except CancelledException as e:
                print(f"Cancelled: {e}")

    def process_matches(self, function, family, monitor):
        matches = []
        for match in lookup_family(family, monitor):
            if match.overall_score >= self.score_threshold:
                return make_all_matches(function, family, [match], monitor)

        return None

    def score_match(self, function_record, family, monitor):
        code_units = 0
        specific_code_units = 0
        mode = HashLookupListMode.FULL
        if function_record.get_specific_hash() == family.get_hash().get_specific_hash():
            specific_code_units = function_record.get_specific_hash_additional_size()
            mode = HashLookupListMode.SPECIFIC

        for fid_hash_quad in family.get_children():
            try:
                monitor.check_cancelled()
                if self.fid_query_service.get_superior_full_relation(function_record, fid_hash_quad):
                    code_units += fid_hash_quad.code_unit_size
            except CancelledException as e:
                print(f"Cancelled: {e}")

        parent_code_units = 0

        for fid_hash_quad in family.get_parents():
            try:
                monitor.check_cancelled()
                if self.fid_query_service.get_inferior_full_relation(fid_hash_quad, function_record):
                    parent_code_units += fid_hash_quad.code_unit_size
            except CancelledException as e:
                print(f"Cancelled: {e}")

        function_score = code_units + 0.67 * specific_code_units

        if function_score + child_code_units + parent_code_units < self.score_threshold:
            return None

        result = HashMatch(function_record, function_score, mode, child_code_units, parent_code_units)

        return result

    def lookup_family(self, family, monitor):
        functions_by_full_hash = self.fid_query_service.find_functions_by_full_hash(family.get_hash().get_full_hash())
        matches = []

        for function_record in functions_by_full_hash:
            try:
                match = score_match(function_record, family, monitor)
                if match is not None:
                    matches.append(match)
            except CancelledException as e:
                print(f"Cancelled: {e}")

        return matches

    def search_function(self, function, monitor):
        family = self.get_family(function, monitor)

        if family is None:
            return FidSearchResult(function, None, [])

        result = process_matches(function, family, monitor)
        if result is None:
            return FidSearchResult(function, None, [])

        return result

    def search(self, monitor):
        results = []

        function_manager = self.program.get_function_manager()
        for function in function_manager.get_functions(True):
            try:
                monitor.check_cancelled()
                family = self.get_family(function, monitor)
                if family is not None:
                    result = process_matches(function, family, monitor)
                    if result is not None:
                        results.append(result)
            except CancelledException as e:
                print(f"Cancelled: {e}")

        return results
```

Please note that Python does not have direct equivalent of Java's `TaskMonitor` and `Cancellexception`. In this translation, I used the built-in exception handling mechanism to simulate these.