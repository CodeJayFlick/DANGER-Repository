class LldbReason:
    class Reasons(enum.Enum):
        NONE = "No reason was given"
        UNKNOWN = "A reason was given, but the manager does not understand it"

    @classmethod
    def get_reason(cls, info):
        return cls.Reasons.UNKNOWN

    def desc(self):
        return "Unknown"


# Usage example:
reason = LldbReason.get_reason("some_info")
print(reason)  # prints: Unknown
