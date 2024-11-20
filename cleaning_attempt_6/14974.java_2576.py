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

