Here is the translation of the Java interface `ICommandService` to a Python class:

```python
class ICommandService:
    def author_created(self, username: str, name: str, email: str) -> None:
        pass  # implement this method in your subclass

    def book_added_to_author(self, title: str, price: float, username: str) -> None:
        pass  # implement this method in your subclass

    def author_name_updated(self, username: str, name: str) -> None:
        pass  # implement this method in your subclass

    def author_username_updated(self, old_username: str, new_username: str) -> None:
        pass  # implement this method in your subclass

    def author_email_updated(self, username: str, email: str) -> None:
        pass  # implement this method in your subclass

    def book_title_updated(self, old_title: str, new_title: str) -> None:
        pass  # implement this method in your subclass

    def book_price_updated(self, title: str, price: float) -> None:
        pass  # implement this method in your subclass
```

Note that I've used the `pass` statement to indicate where you would need to add implementation for each method. You can create a concrete class that inherits from `ICommandService` and implements these methods as needed.