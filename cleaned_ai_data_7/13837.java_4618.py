class VirtualDB:
    def __init__(self):
        self.db = {}

    def connect(self):
        self.db = {}

    def disconnect(self):
        self.db = None

    def read_from_db(self, user_id: str) -> dict or None:
        if user_id in self.db:
            return self.db[user_id]
        return None

    def write_to_db(self, user_account: dict) -> dict:
        user_account['user_id'] = user_account.get('id')
        self.db[user_account['user_id']] = user_account
        return user_account

    def update_db(self, user_account: dict) -> dict:
        return self.write_to_db(user_account)

    def upsert_db(self, user_account: dict) -> dict:
        return self.update_db(user_account)
