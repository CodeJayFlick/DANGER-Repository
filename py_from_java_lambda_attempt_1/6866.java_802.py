Here is the translation of the Java code into Python:

```Python
class DecompilerLocation:
    def __init__(self, program, address, function_entry_point=None, results=None, token=None, line_number=0, char_pos=0):
        self.program = program
        self.address = address
        self.function_entry_point = function_entry_point
        self.results = results
        self.token = token
        self.line_number = line_number
        self.char_pos = char_pos

    def get_function_entry_point(self):
        return self.function_entry_point

    def get_decompile_results(self):
        return self.results

    def get_token(self):
        return self.token

    def get_token_name(self):
        if not hasattr(self, 'token_name'):
            raise AttributeError('Token name is not set')
        return self.token_name

    def __hash__(self):
        result = super().__hash__()
        result += hash((self.char_pos,))
        result += (0 if self.function_entry_point is None else hash(self.function_entry_point))
        result += self.line_number
        result += (0 if self.token_name is None else hash(self.token_name))
        return result

    def __eq__(self, other):
        if not isinstance(other, DecompilerLocation):
            return False
        if super().__ne__(other):
            return False
        if self.char_pos != other.char_pos:
            return False
        if self.line_number != other.line_number:
            return False
        if (not hasattr(self, 'function_entry_point') and not hasattr(other, 'function_entry_point')) or \
           (hasattr(self, 'function_entry_point') and hasattr(other, 'function_entry_point') and self.function_entry_point is None and other.function_entry_point is None) or \
           (self.function_entry_point != other.function_entry_point):
            return False
        if (not hasattr(self, 'token_name') and not hasattr(other, 'token_name')) or \
           (hasattr(self, 'token_name') and hasattr(other, 'token_name') and self.token_name is None and other.token_name is None) or \
           (self.token_name != other.token_name):
            return False
        return True

    def save_state(self, save_state):
        super().save_state(save_state)
        if not hasattr(self, '_function_entry_point'):
            raise AttributeError('Function entry point is not set')
        save_state['_FUNCTION_ENTRY'] = str(self.function_entry_point)
        if not hasattr(self, 'token_name'):
            self.token_name = ''
        save_state['_TOKEN_TEXT'] = self.token_name
        save_state['_LINE_NUM'] = self.line_number
        save_state['_CHAR_POS'] = self.char_pos

    def restore_state(self, program1, save_state):
        super().restore_state(program1, save_state)
        if '_FUNCTION_ENTRY' in save_state:
            addr_str = save_state['_FUNCTION_ENTRY']
            function_entry_point = program1.parse_address(addr_str)[0]
            self.function_entry_point = function_entry_point
        if 'token_name' not in save_state or save_state['token_name'] is None:
            token_name = ''
        else:
            token_name = save_state['token_name']
        self.token_name = token_name
        if '_LINE_NUM' in save_state and '_CHAR_POS' in save_state:
            line_number = int(save_state['_LINE_NUM'])
            char_pos = int(save_state['_CHAR_POS'])
        else:
            line_number, char_pos = 0, 0
        self.line_number, self.char_pos = line_number, char_pos

    def get_line_number(self):
        return self.line_number

    def get_char_position(self):
        return self.char_pos

    def __str__(self):
        buf = f"{type(self).__name__}@{self.address}, line={self.line_number}, character={self.char_pos}, token={self.token_name}"
        return buf
```

Note that the `save_state` and `restore_state` methods are not exactly equivalent to their Java counterparts. In Python, dictionaries (`dict`) are used for storing key-value pairs, whereas in Java, a custom class is often used (in this case, `SaveState`).