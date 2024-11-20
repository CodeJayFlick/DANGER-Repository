class MatchFunctions:
    def __init__(self):
        pass  # non-instantiable

    @staticmethod
    def match_functions(a_program: 'Program', set_a: 'AddressSetView', b_program: 'Program',
                        set_b: 'AddressSetView', minimum_function_size: int, include_one_to_one: bool,
                        include_non_one_to_one: bool, hasher: 'FunctionHasher', monitor):
        function_hashes = {}
        function_matches = []
        a_progf_iter = a_program.get_function_manager().get_functions(set_a, True)
        b_progf_iter = b_program.get_function_manager().get_functions(set_b, True)

        while not monitor.is_cancelled() and a_progf_iter.has_next():
            func = a_progf_iter.next()
            if not func.is_thunk() and func.get_body().num_addresses >= minimum_function_size:
                hash_function(monitor, function_hashes, func, hasher, True)
        
        monitor.set_message("Hashing functions in " + b_program.name)

        while not monitor.is_cancelled() and b_progf_iter.has_next():
            func = b_progf_iter.next()
            if not func.is_thunk() and func.get_body().num_addresses >= minimum_function_size:
                hash_function(monitor, function_hashes, func, hasher, False)
        
        progress = monitor.progress
        monitor.set_maximum(progress + len(function_hashes))
        monitor.set_progress(progress)
        monitor.set_message("Finding function matches")
        for match in function_hashes.values():
            if monitor.is_cancelled():
                break
            a_prog_addrs = match.a_addresses
            b_prog_addrs = match.b_addresses

            if (include_one_to_one and len(a_prog_addrs) == 1 and len(b_prog_addrs) == 1) or \
               (include_non_one_to_one and not (len(a_prog_addrs) == 1 and len(b_prog_addrs) == 1)):
                for a_addr in a_prog_addrs:
                    for b_addr in b_prog_addrs:
                        function_match = MatchedFunctions(
                            a_program, b_program, a_addr, b_addr,
                            len(a_prog_addrs), len(b_prog_addrs),
                            "Code Only Match"
                        )
                        function_matches.append(function_match)

        return function_matches

    @staticmethod
    def match_one_function(a_program: 'Program', entry_point_a: Address, b_program: 'Program',
                           hasher: 'FunctionHasher', monitor):
        return match_functions(a_program, None, b_program, None, hasher, monitor)


class MatchedFunctions:
    def __init__(self, a_prog: 'Program', b_prog: 'Program', a_addr: Address,
                 b_addr: Address, a_match_num: int, b_match_num: str):
        self.a_prog = a_prog
        self.b_prog = b_prog
        self.a_addr = a_addr
        self.b_addr = b_addr
        self.a_match_num = a_match_num
        self.b_match_num = b_match_num

    def get_a_program(self) -> 'Program':
        return self.a_prog

    def get_b_program(self) -> 'Program':
        return self.b_prog

    def get_a_function_address(self) -> Address:
        return self.a_addr

    def get_b_function_address(self) -> Address:
        return self.b_addr

    def get_a_match_num(self) -> int:
        return self.a_match_num

    def get_b_match_num(self) -> int:
        return self.b_match_num


class Match:
    def __init__(self):
        self.a_addresses = []
        self.b_addresses = []

    def add(self, address: Address, is_prog_a: bool):
        if is_prog_a:
            self.a_addresses.append(address)
        else:
            self.b_addresses.append(address)


def hash_function(monitor, function_hashes, function, hasher, is_prog_a):
    hash_value = hasher.hash(function, monitor)

    match = function_hashes.get(hash_value)
    if match is None:
        match = Match()
        function_hashes[hash_value] = match
    match.add(function.entry_point(), is_prog_a)


class FunctionHasher:
    def __init__(self):
        pass  # non-instantiable

    @staticmethod
    def hash(function, monitor) -> int:
        raise NotImplementedError


class Program:
    def get_function_manager(self) -> 'FunctionManager':
        raise NotImplementedError

    def name(self) -> str:
        raise NotImplementedError


class AddressSetView:
    def __init__(self):
        pass  # non-instantiable

    @staticmethod
    def from_addresses(addresses: List[Address]) -> 'AddressSetView':
        raise NotImplementedError


class FunctionManager:
    def get_functions(self, set_a: 'AddressSetView', is_thunk_only: bool) -> Iterator['Function']:
        raise NotImplementedError


class Address:
    pass  # non-instantiable
