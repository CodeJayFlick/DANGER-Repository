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
