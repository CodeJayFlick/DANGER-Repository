class WithdrawMoneyService:
    def __init__(self):
        self.name = "withdrawing Money"

    def get_name(self):
        return self.name

    def process(self, value: str) -> dict:
        if value in ["bad_order", "crashed_order"]:
            print(f"The chapter '{value}' has been started. But the exception has been raised."
                  f" The rollback is about to start {self.name} {value}")
            return {"status": "failure", "result": value}
        else:
            # This line doesn't exist in Java, so I'm assuming you want something here
            pass

# Usage example:

service = WithdrawMoneyService()
print(service.get_name())
