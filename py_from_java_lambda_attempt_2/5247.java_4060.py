Here is the translation of the Java code into Python:

```Python
class CParserUtils:
    def __init__(self):
        pass

    @staticmethod
    def parse_signature(service_provider: ServiceProvider, program: Program, signature_text: str) -> FunctionDefinitionDataType:
        service = service_provider.get_service(DataTypeManagerService)
        return self.parse_signature(service, program, signature_text)

    @staticmethod
    def parse_signature(service: DataTypeManagerService, program: Program, signature_text: str) -> FunctionDefinitionDataType:
        try:
            dt = CParser(program.get_data_type_manager(), False).parse(signature_text + ";")
            if not isinstance(dt, FunctionDefinitionDataType):
                return None
            dt.set_name(signature_parts[1])
            return dt
        except (InvalidNameException | DuplicateNameException) as e:
            Msg.debug(CParserUtils.__class__, "Logging an exception that cannot happen", e)
            return None

    @staticmethod
    def split_function_signature(signature: str) -> list[str]:
        index = signature.rfind(')')
        if index < 0:
            return []
        closure_count = 1
        while --index > 0:
            c = signature[index]
            if c == ' ':
                pass
            elif c == ')':
                closure_count += 1
            elif c == '(':
                closure_count -= 1
            else:
                break

        if closure_count != 0:
            return []

        parts = [signature[:index + 1]]
        signature = signature[index + 1:]
        space_index = signature.rfind(' ')
        if space_index <= 0:
            return []
        parts.append(signature[space_index + 1:])
        parts.insert(0, signature[:space_index])
        return parts

    @staticmethod
    def get_temp_name(length: int) -> str:
        name_chars = ['t'] * length
        return ''.join(name_chars)

    @staticmethod
    def parse_signature(service_provider: ServiceProvider, program: Program, signature_text: str, handle_exceptions: bool) -> FunctionDefinitionDataType:
        data_type_managers = service_provider.get_data_type_managers() if service_provider else [program.get_data_type_manager()]
        parser = CParser(program.get_data_type_manager(), False, data_type_managers)
        parts = self.split_function_signature(signature_text)
        if not parts:
            Msg.debug(CParserUtils.__class__, "Invalid signature: unable to isolate function name", f"{signature_text}")
            return None
        replaced_text = ' '.join([parts[0], get_temp_name(len(parts[1])), parts[2]])
        try:
            dt = parser.parse(replaced_text + ";")
            if not isinstance(dt, FunctionDefinitionDataType):
                return None
            dt.set_name(parts[1])
            return dt
        except (InvalidNameException | DuplicateNameException) as e:
            Msg.debug(CParserUtils.__class__, "Logging an exception that cannot happen", e)
        except Exception as e:
            if not handle_exceptions:
                raise e
            msg = self.handle_parse_problem(e, signature_text)
            if msg is None:
                return None

    @staticmethod
    def get_data_type_managers(service: DataTypeManagerService) -> list[DataTypeManager]:
        if service is None:
            return []
        open_dtmanagers = service.get_data_type_managers()
        return [dtmanager for dtmanager in open_dtmanagers]

    @staticmethod
    def handle_parse_problem(t, function_string):
        if isinstance(t, TokenMgrError):
            return self.generate_token_error_message(t, function_string)
        elif isinstance(t, ParseException):
            return self.generate_parse_exception_message(t, function_string)

    @staticmethod
    def generate_token_error_message(e: TokenMgrError, function_string) -> str:
        message = e.get_message()
        error_index = self.get_token_mgr_error_index_invalid_text(message, function_string)
        if error_index < 0:
            return None

        return self.generate_parsing_exception_message(message, error_index, function_string)

    @staticmethod
    def get_token_mgr_error_index_invalid_text(message: str, function_string) -> int:
        invalid_char_marker = "after : "
        index = message.find(invalid_char_marker)
        if index >= 0:
            remainder = message[index + len(invalid_char_marker):]
            return function_string.index(remainder)

    @staticmethod
    def generate_parsing_exception_message(message: str, error_index: int, function_string) -> str:
        parse_message = ""
        if message is not None:
            # Handle lines that are as big as the screen: -wrap on the given length
            # -remove newlines because the line wrapping utility always breaks on those
            parse_message = message.replace("\n", "  ")
            parse_message = HTMLUtilities.line_wrap_with_html_line_breaks(HTMLUtilities.escape_html(parse_message), 80)
            parse_message += "<br><br>" + parse_message + "<br>"

        success_failure_buffer = StringBuffer()
        if error_index == 0:
            success_failure_buffer.append("<font color=\"red\"><b>")
            success_failure_buffer.append(friendly_encode_html(function_string))
            success_failure_buffer.append("</b></font>")
        else:
            success_failure_buffer.append("<font color=\"black\">")
            success_failure_buffer.append(friendly_encode_html(function_string[:error_index]))
            success_failure_buffer.append("</font>")
            success_failure_buffer.append("<font color=\"red\"><b>")
            success_failure_buffer.append(friendly_encode_html(function_string[error_index:]))
            success_failure_buffer.append("</b></font>")

        if error_index == 0:
            return f"<html>Function signature parse failed{parse_message}<br>{success_failure_buffer}"
        else:
            return f"<html>Function signature parse failed on token starting near character {error_index}<br>{success_failure_buffer}"

    @staticmethod
    def generate_parse_exception_message(pe: ParseException, function_string) -> str:
        if pe.current_token is None:
            return None

        error_index = pe.current_token.begin_column
        if error_index < 0:
            return None

        return self.generate_parsing_exception_message(pe.get_message(), error_index, function_string)
```

Note that this translation assumes you have the following Python modules:

- `ServiceProvider`
- `Program`
- `DataTypeManagerService`
- `FunctionDefinitionDataType`
- `CParser` (which is a class with methods like `parse`, `get_data_type_manager`, etc.)
- `HTMLUtilities` (with methods like `friendly_encode_html`, `line_wrap_with_html_line_breaks`, etc.)

Also, note that this translation does not include the implementation of these modules.