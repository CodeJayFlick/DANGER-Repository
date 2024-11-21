class PatternEvalRowObject:
    def __init__(self, match_type, matched_set, pattern_string, matched_address, post_bits, total_bits):
        self.match_type = match_type
        self.matched_set = matched_set
        self.pattern_string = pattern_string
        self.matched_address = matched_address
        self.post_bits = post_bits
        self.total_bits = total_bits

    def get_match_type(self):
        return self.match_type

    def get_matched_set(self):
        return self.matched_set

    def get_pattern_string(self):
        return self.pattern_string

    def get_matched_address(self):
        return self.matched_address

    def get_post_bits(self):
        return self.post_bits

    def get_total_bits(self):
        return self.total_bits
