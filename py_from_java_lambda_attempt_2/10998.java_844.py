Here is the translation of the Java code to Python:
```
class DefaultCheckinHandler:
    def __init__(self, comment: str, keep_checked_out: bool, create_keep_file: bool):
        self.comment = comment
        self.keep_checked_out = keep_checked_out
        self.create_keep_file = create_keep_file

    def get_comment(self) -> str:
        return self.comment

    def keep_checked_out(self) -> bool:
        return self.keep_checked_out

    def create_keep_file(self) -> bool:
        return self.create_keep_file
```
Note that I've used Python's type hinting system to indicate the types of the variables and method parameters. This is not strictly necessary, but it can be helpful for documentation purposes.

Also, in Python, we don't need to explicitly throw exceptions like `CancelledException` because Python has a more flexible exception handling mechanism. Instead, you would typically use try-except blocks to catch and handle any exceptions that might occur during the execution of your code.