class Account:
    def __init__(self, account_no: int, owner: str):
        self.account_no = account_no
        self.owner = owner
        self.money = 0

    @property
    def money(self) -> float:
        return self._money

    @money.setter
    def money(self, value: float):
        if isinstance(value, (int, float)):
            self._money = value
        else:
            raise ValueError("Money must be a number")

    def copy(self) -> 'Account':
        new_account = Account(self.account_no, self.owner)
        new_account.money = self.money
        return new_account

    def __str__(self):
        return f"Account(account_no={self.account_no}, owner='{self.owner}', money={self.money})"

    def deposit_money(self, amount: float) -> None:
        if isinstance(amount, (int, float)):
            self.money += amount
        else:
            raise ValueError("Amount must be a number")

    def withdraw_money(self, amount: float) -> None:
        if isinstance(amount, (int, float)) and 0 <= self.money - amount:
            self.money -= amount
        else:
            raise RuntimeError("Insufficient account balance")

    def handle_deposit(self, money: float, real_time: bool = False):
        self.deposit_money(money)
        AccountAggregate.put_account(self)
        if real_time:
            print("Some external api for only realtime execution could be called here.")

    def handle_withdrawal(self, money: float, real_time: bool = False) -> None:
        if isinstance(money, (int, float)) and 0 <= self.money - money:
            self.withdraw_money(money)
            AccountAggregate.put_account(self)
            if real_time:
                print("Some external api for only realtime execution could be called here.")
        else:
            raise RuntimeError("Insufficient account balance")

    def handle_event(self, event: 'MoneyDepositEvent'):
        if isinstance(event, MoneyDepositEvent):
            self.handle_deposit(event.money, event.real_time)
        else:
            raise ValueError("Invalid event type")

    def handle_transfer_from(self, money_transfer_event: 'MoneyTransferEvent') -> None:
        if isinstance(money_transfer_event, MoneyTransferEvent):
            self.handle_withdrawal(money_transfer_event.money, money_transfer_event.real_time)

    def handle_transfer_to(self, money_transfer_event: 'MoneyTransferEvent'):
        if isinstance(money_transfer_event, MoneyTransferEvent):
            self.handle_deposit(money_transfer_event.money, money_transfer_event.real_time)
