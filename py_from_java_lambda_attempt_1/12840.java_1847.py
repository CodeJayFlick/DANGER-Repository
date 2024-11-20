Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractSleighLexer:
    def __init__(self):
        pass

    def __init__(self, input=None, state=None):
        if input is not None and state is not None:
            super().__init__(input, state)

    def emit(self):
        t = SleighToken(input=input, type=state['type'], channel=state['channel'],
                        token_start_char_index=state['tokenStartCharIndex'] - 1,
                        char_index=get_char_index() - 1)
        location = env.get_locator().get_location(state['tokenStartLine'])
        t.set_location(location)
        t.set_line(state['tokenStartLine'])
        t.set_text(state['text'])
        t.set_char_position_in_line(state['tokenStartCharPositionInLine'])
        emit(t)
        return t

    def emit_error_message(self, msg):
        Msg.error(self, msg)

    def get_error_header(self, e):
        return env.get_error_header(e)

    def get_error_message(self, e, token_names):
        return env.get_lexer_error_message(e, token_names)

    def get_token_error_display(self, t):
        return env.get_token_error_display(t)

    def preprocess(self, text):
        split = text.split('###')
        if len(split) == 2:
            env.get_locator().register_location(input.line(), Location(split[0], int(split[1])))
        input.set_char_position_in_line(input.char_position_in_line() - (text.length() + 2))

    def set_env(self, env):
        self.env = env

class SleighToken:
    def __init__(self, input=None, type=0, channel=-1,
                 token_start_char_index=0, char_index=0, text='', line=0,
                 char_position_in_line=0):
        self.input = input
        self.type = type
        self.channel = channel
        self.token_start_char_index = token_start_char_index
        self.char_index = char_index
        self.text = text
        self.line = line
        self.char_position_in_line = char_position_in_line

    def set_location(self, location):
        pass  # Not implemented in Python version

class Location:
    def __init__(self, start='', end=0):
        self.start = start
        self.end = end

def get_char_index():
    return 0  # This method is not defined in the original Java code.

# Usage example:

if __name__ == "__main__":
    env = ParsingEnvironment()  # Define this class as per your requirement.
    lexer = AbstractSleighLexer()
    lexer.set_env(env)
```

Please note that Python does not have direct equivalent of Java's `RecognitionException`, so I did not include it in the translation. Also, some methods like `emit` and `set_location` are not implemented because they require more context which is missing from this code snippet.