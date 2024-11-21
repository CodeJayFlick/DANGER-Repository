import json

class ValidationExceptionMapper:
    def __init__(self):
        pass

    @staticmethod
    def to_response(exception: Exception) -> dict:
        if isinstance(exception, ConstraintViolationException):
            status = "BAD_REQUEST"
            for violation in exception.get_constraint_violations():
                for node in violation.get_property_path():
                    kind = node.get_kind()
                    if kind == 'RETURN_VALUE':
                        status = "INTERNAL_SERVER_ERROR"

            return {
                "status": status,
                "reason_phrase": f"Validation Error: {exception.get_message()}",
                "message": exception.get_message(),
                "error": True
            }

        return {
            "status": "INTERNAL_SERVER_ERROR",
            "reason_phrase": "Internal Server Error",
            "message": self.unwrap_exception(exception),
            "error": True
        }

    @staticmethod
    def unwrap_exception(t: Exception) -> str:
        if t is None:
            return ""

        sb = StringBuffer()
        do_unwrap_exception(sb, t)
        return sb.toString()

    @staticmethod
    def do_unwrap_exception(sb: StringBuffer, t: Exception):
        if t is None:
            return

        sb.append(str(t))
        if t.get_cause() and t != t.get_cause():
            sb.append('[')
            ValidationExceptionMapper.do_unwrap_exception(sb, t.get_cause())
            sb.append(']')

class StringBuffer:
    def __init__(self):
        self.sb = ""

    def append(self, s: str) -> None:
        self.sb += s

    def toString(self) -> str:
        return self.sb
