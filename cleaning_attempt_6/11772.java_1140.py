class ParseException(Exception):
    def __init__(self, current_token_val=None, expected_token_sequences_val=None, token_image_val=None):
        super().__init__()
        self.special_constructor = True
        self.current_token = current_token_val
        self.expected_token_sequences = expected_token_sequences_val
        self.token_image = token_image_val

    def __init__(self):
        super().__init__()
        self.special_constructor = False

    def __init__(self, message):
        super().__init__(message)
        self.special_constructor = False

    @property
    def special_constructor(self):
        return self._special_constructor

    @special_constructor.setter
    def special_constructor(self, value):
        if not isinstance(value, bool):
            raise TypeError("Special constructor must be a boolean")
        self._special_constructor = value

    @property
    def current_token(self):
        return self._current_token

    @current_token.setter
    def current_token(self, value):
        if not isinstance(value, Token):
            raise TypeError("Current token must be an instance of Token class")
        self._current_token = value

    @property
    def expected_token_sequences(self):
        return self._expected_token_sequences

    @expected_token_sequences.setter
    def expected_token_sequences(self, value):
        if not isinstance(value, list) or any(not isinstance(seq, list) for seq in value):
            raise TypeError("Expected token sequences must be a list of lists")
        self._expected_token_sequences = value

    @property
    def token_image(self):
        return self._token_image

    @token_image.setter
    def token_image(self, value):
        if not isinstance(value, list) or any(not isinstance(img, str) for img in value):
            raise TypeError("Token image must be a list of strings")
        self._token_image = value

    def get_message(self):
        if not self.special_constructor:
            return super().get_message()
        expected_str = ""
        max_size = 0
        for seq in self.expected_token_sequences:
            if len(seq) > max_size:
                max_size = len(seq)
            for token in seq:
                expected_str += f"{self.token_image[token]} "
            if seq[-1] != 0:
                expected_str += "... "
            expected_str += "\n     "
        retval = "Encountered \""
        current_token = self.current_token.next
        for i in range(max_size):
            if i > 0:
                retval += " "
            if current_token.kind == 0:
                retval += f"{self.token_image[0]}"
                break
            retval += add_escapes(current_token.image)
            current_token = current_token.next
        retval += "\" at line " + str(self.current_token.next.begin_line) + ", column " + str(self.current_token.next.begin_column)
        if len(self.expected_token_sequences) == 1:
            retval += ".\n"
        else:
            retval += ".\n     "
        return f"{retval}\nWas expecting one of:\n{expected_str}"

    def add_escapes(self, str):
        retval = ""
        for char in str:
            if char < 0x20 or char > 0x7e:
                s = "0000" + hex(char)[2:]
                return f"\\u{s[-4:]}"
            elif char == 0:
                continue
            elif char == '\b':
                retval += "\\b"
            elif char == '\t':
                retval += "\\t"
            elif char == '\n':
                retval += "\\n"
            elif char == '\f':
                retval += "\\f"
            elif char == '\r':
                retval += "\\r"
            elif char == '"':
                retval += "\"\\\""
            elif char == "'":
                retval += "\\'"
            elif char == '\\':
                retval += "\\\\"
            else:
                retval += str(char)
        return retval

class Token:
    def __init__(self, kind=None):
        self.kind = kind
