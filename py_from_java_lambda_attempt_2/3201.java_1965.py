Here is the translation of the given Java code into Python:

```Python
class RemoveFunctionTagCmd:
    def __init__(self, tag_name: str, entry_point: int):
        self.tag_name = tag_name
        self.entry_point = entry_point

    def apply_to(self, program_db):
        function_manager = program_db.get_function_manager()
        function = function_manager.get_function_at(entry_point)
        if hasattr(function, 'remove_tag'):
            function.remove_tag(tag_name)
            return True
        else:
            print(f"Error: Function at {entry_point} does not have a remove_tag method.")
            return False

    def get_name(self):
        return "Remove Tag From Function"

    def get_status_msg(self):
        return None


# Example usage:

program_db = ProgramDB()  # This is just an example, you would need to implement this class
entry_point = 0x12345678
tag_name = 'my_tag'

cmd = RemoveFunctionTagCmd(tag_name, entry_point)
result = cmd.apply_to(program_db)

if result:
    print("Tag removed successfully.")
else:
    print("Error removing tag.")
```

Please note that Python does not have direct equivalent of Java's `DomainObject`, `ProgramDB` and other classes. The above code is a simple translation and may require modifications based on the actual usage in your program.