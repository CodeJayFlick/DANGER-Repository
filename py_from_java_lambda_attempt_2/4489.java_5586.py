Here is the translation of the Java code into Python:

```Python
class MatchData:
    def __init__(self):
        pass  # non-instantiable

    @staticmethod
    def match_data(a_program: 'Program', set_a: 'AddressSetView',
                   b_program: 'Program', set_b: 'AddressSetView',
                   minimum_data_size: int, maximum_data_size: int,
                   alignment: int, skip_homogenous_data: bool,
                   include_one_to_one: bool, include_non_one_to_one: bool,
                   monitor: 'TaskMonitor') -> List['MatchedData']:
        if alignment < 1:
            alignment = 1

        set_a = MatchData.remove_uninitialized_blocks(a_program, set_a)
        set_b = MatchData.remove_uninitialized_blocks(b_program, set_b)

        result = []

        source_trie = extract_source_hashes(a_program, set_a,
                                             minimum_data_size, maximum_data_size,
                                             skip_homogenous_data, monitor)

        find_destination_matches(a_program, b_program, set_b,
                                  minimum_data_size, alignment,
                                  include_one_to_one, include_non_one_to_one,
                                  result, source_trie, monitor)

        monitor.set_message("")
        return result

    @staticmethod
    def extract_source_hashes(a_program: 'Program', set_a: 'AddressSetView',
                              minimum_data_size: int, maximum_data_size: int,
                              skip_homogenous_data: bool, monitor: 'TaskMonitor') -> 'ByteTrie':
        trie = ByteTrie()

        num_defined_data = a_program.get_listing().get_num_defined_data()
        monitor.initialize(num_defined_data)
        monitor.set_message("(1 of 4) Compiling source data")

        for data in a_program.get_listing().get_defined_data(set_a, True):
            if monitor.is_cancelled():
                break
            monitor.increment_progress(1)

            length = data.get_length()

            if (length >= minimum_data_size and length <= maximum_data_size):
                do_hash = True

                try:
                    bytes = data.get_bytes()
                except MemoryAccessException as e:
                    raise RuntimeException(e)
                first = bytes[0]
                for ii in range(1, len(bytes)):
                    if bytes[ii] != first:
                        different = True
                        break
                do_hash = different and not skip_homogenous_data

                if do_hash or (not skip_homogenous_data):
                    try:
                        bytes = data.get_bytes()
                    except MemoryAccessException as e:
                        raise RuntimeException(e)
                    node = trie.find(bytes)

                    if node is None or not node.is_terminal():
                        set = {data.get_address()}
                        trie.add(bytes, Pair(set, set))
                    else:
                        node.item.first.update({data.get_address()})

        return trie

    @staticmethod
    def find_destination_matches(a_program: 'Program', b_program: 'Program',
                                 set_b: 'AddressSetView', minimum_data_size: int,
                                 alignment: int, include_one_to_one: bool,
                                 include_non_oneToOne: bool, result: List['MatchedData'],
                                 source_trie: 'ByteTrie', monitor: 'TaskMonitor') -> None:
        search_results = []

        try:
            monitor.set_message("(2 of 4) Search destination bytes")
            search_results = source_trie.search(b_program.get_memory(), set_b, monitor)
        except MemoryAccessException as e:
            raise RuntimeException(e)

        data_extents = AddressSet()
        data_starts = AddressSet()

        for defined_data in b_program.get_listing().get_defined_data(True):
            try:
                bytes = defined_data.get_bytes()
            except MemoryAccessException as e:
                raise RuntimeException(e)
            data_extents.update({defined_data.get_min_address(), defined_data.get_max_address()})
            data_starts.add(defined_data.get_min_address())

        monitor.initialize(len(search_results))
        monitor.set_message("(3 of 4) Post-process search results")

        for i, (search_result, _) in enumerate(zip(search_results)):
            if monitor.is_cancelled():
                break
            monitor.increment_progress(1)

            b_location = search_result.position

            if b_location.get_offset() % alignment != 0:
                continue

            if not data_starts.contains(b_location) and data_extents.contains(b_location):
                continue

            item = search_result.item
            set_b_locations = item.second
            set_b_locations.add(b_location)

        MatchData.generate_matches(result, a_program, b_program,
                                    search_results, alignment, include_one_to_one,
                                    include_non_OneToOne, monitor)

    @staticmethod
    def generate_matches(result: List['MatchedData'], a_program: 'Program',
                         b_program: 'Program', search_results: List[SearchResult],
                         alignment: int, include_one_to_one: bool,
                         include_non_oneToOne: bool, monitor: 'TaskMonitor') -> None:
        done = set()

        for i, (search_result, _) in enumerate(zip(search_results)):
            if monitor.is_cancelled():
                break
            monitor.increment_progress(1)

            node = search_result.node

            if not done.contains(node):
                pair = search_result.item
                a_locations = pair.first
                b_locations = pair.second
                a_size = len(a_locations)
                b_size = len(b_locations)

                process_result = (include_one_to_one and a_size == 1 and b_size == 1) or \
                                 (include_non_OneToOne and (a_size > 1 or b_size > 1))

                if process_result:
                    for a_location in a_locations:
                        for b_location in b_locations:
                            try:
                                bytes = a_program.get_listing().get_data_at(a_location).get_bytes()
                            except MemoryAccessException as e:
                                raise RuntimeException(e)
                            try:
                                bytes = b_program.get_listing().get_data_at(b_location).get_bytes()
                            except MemoryAccessException as e:
                                raise RuntimeException(e)

                            matched_data = MatchedData(a_program, b_program,
                                                      a_location, b_location,
                                                      a_program.get_listing().get_data_at(a_location),
                                                      b_program.get_listing().get_data_at(b_location), a_size, b_size)
                            result.append(matched_data)

                done.add(node)

    @staticmethod
    def remove_uninitialized_blocks(program: 'Program', addr_set: 'AddressSetView') -> AddressSetView:
        return addr_set.intersect(program.get_memory().get_loaded_and_initialized_address_set())
```

Note that this translation is not perfect, as Python does not support Java's `@static` method decorator.