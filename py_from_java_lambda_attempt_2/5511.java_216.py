Here is the translation of the Java code to Python:
```
class PcodeFieldMouseHandler:
    SUPPORTED_CLASSES = [PcodeFieldLocation]

    def field_element_clicked(self, clicked_object: object, source_navigatable: Navigatable,
                               program_location: ProgramLocation, mouse_event: MouseEvent,
                               service_provider: ServiceProvider) -> bool:
        if mouse_event.get_click_count() != 2 or mouse_event.get_button() != MouseEvent.BUTTON1:
            return False

        pcode_location = PcodeFieldLocation(program_location)
        pcode_strings = pcode_location.get_pcode_strings()
        row = pcode_location.get_row()
        pcode_string = pcode_strings[row]
        column = pcode_location.get_char_offset()
        word = find_word(pcode_string, column)

        return self.check_word(word, service_provider, source_navigatable)

    def check_word(self, word: str, service_provider: ServiceProvider,
                   source_navigatable: Navigatable) -> bool:
        if not word:
            return False

        location = source_navigatable.get_location()
        goto_service = service_provider.get_service(GoToService)
        query_data = QueryData(word, False)

        return goto_service.go_to_query(source_navigatable, location.get_address(), query_data, None, None)

    def get_supported_program_locations(self) -> list:
        return self.SUPPORTED_CLASSES


class Navigatable:
    pass

class ProgramLocation:
    pass

class PcodeFieldLocation(ProgramLocation):
    pass

class GoToService:
    pass

class QueryData:
    def __init__(self, word: str, is_regex: bool):
        self.word = word
        self.is_regex = is_regex


def find_word(pcode_string: str, column: int) -> str:
    # implement this function to find the word at the given column in pcode string
    pass

class MouseEvent:
    BUTTON1 = 0x01

if __name__ == "__main__":
    mouse_handler = PcodeFieldMouseHandler()
    navigatable = Navigatable()
    program_location = ProgramLocation()
    service_provider = ServiceProvider()

    # test the code
    clicked_object = object()  # replace with actual value
    mouse_event = MouseEvent()
    result = mouse_handler.field_element_clicked(clicked_object, navigatable,
                                                    program_location, mouse_event, service_provider)
    print(result)

```
Note that I had to make some assumptions about the Java classes and methods since they were not provided. For example, `PcodeFieldLocation`, `Navigatable`, `ProgramLocation`, `GoToService`, and `QueryData` are all Python classes with similar names but different implementations. Similarly, `find_word` is a placeholder function that needs to be implemented.

Also note that this translation assumes that the Java code was written in a style consistent with good coding practices (e.g., using meaningful variable names, following PEP 8 guidelines). If the original Java code had issues or inconsistencies, they may have been carried over into the Python version.