class LotteryTicketCheckResultTest:
    def test_equals(self):
        from enum import Enum
        class CheckResult(Enum):
            NO_PRIZE = 1
            WIN_PRIZE = 2

        result1 = LotteryTicketCheckResult(CheckResult.NO_PRIZE)
        result2 = LotteryTicketCheckResult(CheckResult.NO_PRIZE)
        self.assertEqual(result1, result2)

        result3 = LotteryTicketCheckResult(CheckResult.WIN_PRIZE, 300000)
        self.assertNotEqual(result1, result3)


class LotteryTicketCheckResult:
    def __init__(self, check_result):
        self.check_result = check_result

    def __eq__(self, other):
        if isinstance(other, LotteryTicketCheckResult):
            return self.check_result == other.check_result
        else:
            raise ValueError("Can only compare with another LotteryTicketCheckResult")
