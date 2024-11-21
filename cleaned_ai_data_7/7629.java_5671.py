class FidSearchResult:
    def __init__(self, func: 'Function', hash_quad: 'FidHashQuad', matches: list):
        self.function = func
        self.hash_quad = hash_quad
        self.matches = matches

    def filter_by_symbol_prefix(self, prefix: str) -> None:
        result = []
        for match in self.matches:
            function_record = match.get_function_record()
            if not function_record.name.startswith(prefix):
                result.append(match)
        self.matches = result  # Replace old matches list with filtered list
