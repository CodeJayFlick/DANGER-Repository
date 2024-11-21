class EffResetTitle:
    def __init__(self):
        self.recipients = None

    @staticmethod
    def register_effect():
        pass  # equivalent to Skript.registerEffect in Java

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) > 0:
            self.recipients = exprs[0]
        return True

    def execute(self, e):
        for recipient in self.recipients.get_array(e):
            recipient.reset_title()

    def __str__(self, e=None, debug=False):
        return f"reset the title of {self.recipients.__str__(e, debug)}"


# equivalent to Java annotations
class Name:
    pass

class Description:
    pass

class Examples:
    pass

class Since:
    pass


EffResetTitle.register_effect()
