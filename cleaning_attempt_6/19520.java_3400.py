class CommandExpression:
    def __init__(self):
        self.what = None

    @property
    def what(self):
        return self._what

    @what.setter
    def what(self, value):
        self._what = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not (is_player_command_preprocess_event(parse_result) or is_server_command_event(parse_result)):
            if self.what != 2:
                raise ValueError("The 'command' expression can only be used in a command event")
            return False
        return True

    def get(self, e):
        s = None
        if isinstance(e, PlayerCommandPreprocessEvent):
            s = ((PlayerCommandPreprocessEvent) e).get_message().strip()[1:]
        elif isinstance(e, ServerCommandEvent):
            s = ((ServerCommandEvent) e).get_command().strip()
        else:
            return []
        
        if self.what == 0:
            return [s]
        c = s.find(' ')
        if self.what == 2:
            if c == -1:
                return []
            return [s[c + 1:].strip()]
        assert self.what == 1
        return [c == -1 and s or s[:c]]

    def is_single(self):
        return True

    def get_return_type(self):
        from typing import ClassVar
        return ClassVar(str)

    def __str__(self, e=None, debug=False):
        if self.what == 0:
            return "the full command"
        elif self.what == 1:
            return "the command"
        else:
            return "the arguments"

def is_player_command_preprocess_event(parse_result):
    # implement this function
    pass

def is_server_command_event(parse_result):
    # implement this function
    pass
