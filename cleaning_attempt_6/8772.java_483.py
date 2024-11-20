class SymbolNameProgramCorrelator:
    def __init__(self, service_provider, source_program, source_address_set,
                 destination_program, destination_address_set, options, name, one_to_one):
        self.name = name
        self.one_to_one = one_to_one

    def do_correlate(self, match_set, monitor):
        min_symbol_name_length = get_options().get_int('MIN_SYMBOL_NAME_LENGTH', 10)
        include_externals = get_options().get_bool('INCLUDE_EXTERNAL_SYMBOLS', True)

        matched_symbols = MatchSymbol.match_symbol(source_program,
                                                     source_address_set,
                                                     destination_program,
                                                     destination_address_set,
                                                     min_symbol_name_length,
                                                     one_to_one,
                                                     include_externals,
                                                     monitor)

        match_score_map = {}

        for matched_symbol in matched_symbols:
            if monitor.check_cancelled():
                break
            address_match = AddressMatch(matched_symbol)
            score_factor = matched_symbol.get_match_count()
            previous_score_factor = match_score_map.get(address_match, None)
            if previous_score_factor is None or score_factor < previous_score_factor:
                match_score_map[address_match] = score_factor

        for address_match in match_score_map.keys():
            monitor.check_cancelled()
            VTMatchInfo.match_set.add_match(generate_match_from_matched_symbol(match_set,
                                                                               address_match.a_addr,
                                                                               address_match.b_addr,
                                                                               match_score_map.get(address_match),
                                                                               address_match.match_type))

    class AddressMatch:
        def __init__(self, matched_symbol):
            self.match_type = matched_symbol.get_match_type()
            self.a_addr = matched_symbol.get_a_symbol_address()
            self.b_addr = matched_symbol.get_b_symbol_address()

        def __hash__(self):
            return hash((self.a_addr, self.b_addr, self.match_type))

        def __eq__(self, other):
            if self is other:
                return True
            if not isinstance(other, AddressMatch):
                return False
            return (self.a_addr == other.a_addr and
                    self.b_addr == other.b_addr and
                    self.match_type == other.match_type)

    def generate_match_from_matched_symbol(self, match_set, source_address,
                                            destination_address, score_factor, match_type):
        if match_type == 'FUNCTION':
            source_function = source_program.get_function_manager().get_function_at(source_address)
            destination_function = destination_program.get_function_manager().get_function_at(destination_address)

            source_length = len(source_function.body)
            destination_length = len(destination_function.body)
            association_type = VTAssociationType.FUNCTION
        else:
            source_data = source_program.get_listing().data_at(source_address)
            destination_data = destination_program.get_listing().data_at(destination_address)

            source_length = len(source_data)
            destination_length = len(destination_data)
            association_type = VTAssociationType.DATA

        match = VTMatchInfo(match_set)
        match.similarity_score = VTScore(1.0)
        match.confidence_score = VTScore(score_factor / 10.0)

        match.source_address = source_address
        match.destination_address = destination_address
        match.source_length = source_length
        match.destination_length = destination_length
        match.tag = None
        match.association_type = association_type

        return match


class VTMatchInfo:
    def __init__(self, match_set):
        self.match_set = match_set

    # Other methods and properties...
