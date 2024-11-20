class StringAndScores:
    def __init__(self, str, is_lower_case_model):
        self.original_string = str
        if not isinstance(str, str):
            raise TypeError("str must be a string")
        self.scored_string = str.lower() if is_lower_case_model else str

        self.ascii_codes_for_string = [ord(c) for c in self.scored_string]
        self.ngram_score = -100.0
        self.score_threshold = 10.0

    def normalize_and_store_ascii_codes(self):
        intermediate_string = self.scored_string
        if not all(ord(c) < 128 for c in self.scored_string):
            intermediate_string = self.replace_invalid_ascii(self.scored_string)
        self.scored_string = self.normalize_spaces(intermediate_string)

    def replace_invalid_ascii(self, string):
        bad_chars = [c for c in string if ord(c) > 127]
        ascii_string = ''.join([chr(ord(c)) if ord(c) < 128 else ' ' for c in string])
        msg = f"Warning: found non-ASCII character(s) while analyzing '{self.scored_string}' --replacing with space characters during analysis. Char values: {bad_chars}"
        print(msg)
        return ascii_string

    def translate_to_ascii_codes(self):
        self.ascii_codes_for_string = [ord(c) for c in self.scored_string]

    def normalize_spaces(self, str):
        new_str = str.strip()
        while '  ' in new_str:
            new_str = new_str.replace('   ', ' ')
        return new_str

    def set_ngram_score(self, ng_sc):
        self.ngram_score = ng_sc

    def set_score_threshold(self, thresh):
        self.score_threshold = thresh

    @property
    def original_string(self):
        return self._original_string

    @original_string.setter
    def original_string(self, value):
        if not isinstance(value, str):
            raise TypeError("str must be a string")
        self._original_string = value

    @property
    def scored_string(self):
        return self._scored_string

    @scored_string.setter
    def scored_string(self, value):
        self._scored_string = value

    @property
    def ngram_score(self):
        return self._ngram_score

    @ngram_score.setter
    def ngram_score(self, ng_sc):
        self._ngram_score = ng_sc

    @property
    def score_threshold(self):
        return self._score_threshold

    @score_threshold.setter
    def score_threshold(self, thresh):
        self._score_threshold = thresh

    def is_score_above_threshold(self):
        return self.ngram_score > self.score_threshold

    def __eq__(self, other):
        if isinstance(other, StringAndScores):
            return self.original_string == other.original_string
        return False

    def __hash__(self):
        return hash(self.original_string)

    def __str__(self):
        out_str = f"OrigString={self.original_string}, ScoredString={self.scored_string}, ASCII="
        for code in self.ascii_codes_for_string:
            out_str += str(code) + " "
        out_str += f", ngScore={self.ngram_score}, threshold={self.score_threshold}"
        return out_str

    def summary_to_string(self):
        return f"{self.ngram_score}\t{self.original_string}"
