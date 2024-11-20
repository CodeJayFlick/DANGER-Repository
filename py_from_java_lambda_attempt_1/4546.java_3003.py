Here is the translation of the Java interface into a Python class:

```Python
class GhidraScriptService:
    def run_script(self, script_name: str, listener=None):
        # Implement your logic here for running scripts.
        pass

    def refresh_script_list(self):
        # Implement your logic here to refresh the list of available scripts.
        pass

    def try_to_edit_file_in_eclipse(self, file_path: str) -> bool:
        """
        Attempts to edit the provided file in Eclipse.

        Args:
            file_path (str): The path to the file to be edited in Eclipse.

        Returns:
            bool: True if the file opened in Eclipse; otherwise, false.
        """
        # Implement your logic here for editing files in Eclipse. For now, just return False as an example.
        return False
```

Please note that Python does not have direct equivalent of Java's interface concept. Instead, we can use abstract classes or protocols to define the methods a class must implement. In this case, I've used a regular class with placeholder implementations for the methods defined in the original Java code.