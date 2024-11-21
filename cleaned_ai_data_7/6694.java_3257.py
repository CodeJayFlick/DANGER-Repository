class Sequence:
    def __init__(self, sequence: str, count: int):
        self.sequence = sequence
        self.count = count

    @property
    def get_sequence(self) -> str:
        return self.sequence

    @property
    def get_count(self) -> int:
        return self.count

    def index_after_first_instance(self, prefix_sequence: list) -> int:
        if not prefix_sequence:
            return 0
        
        for item in prefix_sequence:
            try:
                symbol = self.sequence[item['index']:item['index']+1]
                if symbol != item['symbol']:
                    return -1
                break
            except IndexError:
                return -1
        else:
            return len(self.sequence)
