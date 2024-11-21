class VTAbstractReferenceProgramCorrelator:
    def __init__(self, service_provider, source_program, 
                 source_address_set, destination_program,
                 destination_address_set, correlator_name, options):
        self.correlator_name = correlator_name
        self.source_program = source_program
        self.destination_program = destination_program

        self.src_vectors_by_address = {}
        self.dest_vectors_by_address = {}

    def get_name(self):
        return self.correlator_name

    @staticmethod
    def score_comparator(o1, o2):
        if not isinstance(o1, VTMatchInfo) or not isinstance(o2, VTMatchInfo):
            raise ValueError("Invalid input")
        return (o2.get_similarity_score().get_score() - 
                o1.get_similarity_score().get_score())

    @staticmethod
    def refine(result_list):
        result_list.sort(key=lambda x: x.get_similarity_score())
        top_n = min(TOP_N + 1, len(result_list))
        result_list = result_list[:top_n]
        
        if len(result_list) > 1:
            previous_score = result_list[0].get_similarity_score().get_score()
            cutoff_index = 1
            for i in range(1, len(result_list)):
                current_score = result_list[i].get_similarity_score().get_score()
                if abs(current_score - previous_score) < EQUALS_EPSILON:
                    break
                previous_score = current_score
                cutoff_index += 1
            
            top_n = min(TOP_N, cutoff_index)
            result_list = result_list[:top_n]
        
        return result_list

    def do_correlate(self, match_set, monitor):
        if not isinstance(match_set, VTMatchSet) or not callable(monitor):
            raise ValueError("Invalid input")
        self.extract_reference_features(match_set, monitor)

    @staticmethod
    def accumulate_function_references(depth, list, program, address):
        if depth >= MAX_DEPTH:
            return
        
        function_manager = program.get_function_manager()
        code_unit = program.get_listing().get_code_unit_at(address)
        
        if isinstance(code_unit, Instruction):
            function = function_manager.get_function_containing(address)
            
            if function is not None and function.is_thunk():
                address_entry_point = function.get_entry_point()
                accumulate_function_references(depth + 1, list, program, address_entry_point)
            else:
                list.add(function)

    @staticmethod
    def get_match_sets(session):
        match_set_list = []
        
        for ms in session.get_match_sets():
            if isinstance(ms, VTMatchSet) and not ms.is_empty():
                match_set_list.append(ms)
        
        return match_set_list

    def extract_reference_features(self, match_set, monitor):
        src_vectors_by_address = {}
        dest_vectors_by_address = {}

        function_manager_src = self.source_program.get_function_manager()
        function_manager_dest = self.destination_program.get_function_manager()

        total_matches = Counter(0)

        for ms in get_match_sets(match_set.session):
            if isinstance(ms, VTMatchSet) and not ms.is_empty():
                source_ref_map = {}
                destination_ref_map = {}

                for match in ms.matches:
                    monitor.check_cancelled()
                    monitor.increment_progress(1)
                    
                    self.accumulate_match_function_references(source_ref_map,
                                                                 destination_ref_map,
                                                                 match)

        feature_id = 0

        for addr, vector in src_vectors_by_address.items():
            total_refs = count_function_refs(self.source_program, addr)
            num_entries = len(vector.hash_values())
            
            while total_refs - num_entries > 0:
                vector.add_hash(feature_id, unique_weight)
                feature_id += 1
        
        for addr, vector in dest_vectors_by_address.items():
            total_refs = count_function_refs(self.destination_program, addr)
            num_entries = len(vector.hash_values())

            while total_refs - num_entries > 0:
                vector.add_hash(feature_id, unique_weight)
                feature_id += 1

    def accumulate_match_function_references(self,
                                               source_ref_map,
                                               destination_ref_map,
                                               match):
        if not isinstance(match, VTMatch) or not callable(monitor):
            raise ValueError("Invalid input")
        
        association = match.association
        addr_source = association.get_source_address()
        addr_destination = association.get_destination_address()

        if not self.is_expected_ref_type(association.type):
            return
        
        source_references = set()
        destination_references = set()

        accumulate_function_references(0, source_references,
                                         self.source_program, addr_source)
        
        accumulate_function_references(0, destination_references,
                                         self.destination_program, addr_destination)

        if len(source_references) == 0 or len(destination_references) == 0:
            return
        
        source_ref_map[match] = source_references
        destination_ref_map[match] = destination_references

    def count_function_refs(self, program, address):
        function_manager = program.get_function_manager()
        code_unit_iterator = program.get_listing().get_code_units(function_manager.
                                                                 get_function_at(address).body,
                                                                  True)
        
        total_refs = 0
        while code_unit_iterator.has_next():
            code_unit = code_unit_iterator.next()
            
            references_from = code_unit.references_from
            
            for reference in references_from:
                if self.is_expected_ref_type(reference):
                    total_refs += 1
        
        return total_refs

    def is_expected_ref_type(self, ref):
        pass
