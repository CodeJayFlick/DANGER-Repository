Here is the translation of the Java code to Python:

```Python
class DomainServicesImpl:
    def purchase(self, user_name: str, item_name: str) -> 'ReceiptViewModel':
        if not self._validate_user(user_name):
            return InvalidUser(user_name)

        account = Db.getInstance().find_account_by_username(user_name)
        return self.purchase(account=account, user=user_name, item=item_name)

    def purchase(self, user: str, account: dict, item_name: str) -> 'ReceiptViewModel':
        if not self._validate_item(item_name):
            return OutOfStock(user, item_name)

        receipt = Db.getInstance().find_product_by_itemname(item_name)
        if receipt is None:
            return receipt

        transaction = account['withdrawal'](receipt['price'])
        if transaction is None:
            return InsufficientFunds(user, account['amount'], item_name)

        return receipt


class InvalidUser:
    def __init__(self, user_name: str):
        self.user_name = user_name


class OutOfStock:
    def __init__(self, user: str, item_name: str):
        self.user = user
        self.item_name = item_name


class InsufficientFunds:
    def __init__(self, user: str, account_amount: float, item_name: str):
        self.user = user
        self.account_amount = account_amount
        self.item_name = item_name

```

Note that I've made some assumptions about the structure of your `Db` class and its methods. In particular, I assumed that it has an instance method called `getInstance()` which returns a singleton-like object, as well as methods like `find_user_by_username()`, `find_account_by_username()`, and `find_product_by_itemname()`. You may need to adjust the code if these assumptions are incorrect.

I also made some guesses about how your classes work. For example, I assumed that `ReceiptViewModel` is a class with its own logic for handling receipts, rather than just being an object that contains receipt data. If this assumption is wrong, you'll need to modify the code accordingly.

Finally, note that Python does not have direct support for Java-style interfaces or abstract classes. Instead, we can use abstract base classes (ABCs) from the `abc` module to define a common interface for multiple subclasses.