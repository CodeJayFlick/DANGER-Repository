Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch
from lottery_service import LotteryAdministration, LotteryService, WireTransfers


class TestLottery(unittest.TestCase):

    def setUp(self):
        self.administration = LotteryAdministration()
        self.service = LotteryService()
        self.wire_transfers = WireTransfers()

    @patch('lottery_service.LotteryAdministration.reset_lottery')
    def test_lottery(self, reset_lottery_mock):
        # admin resets the lottery
        self.administration.reset_lottery()
        self.assertEqual(0, len(self.administration.get_all_submitted_tickets()))

        # players submit the lottery tickets
        ticket1 = self.service.submit_ticket(LotteryTestUtils.create_lottery_ticket("cvt@bbb.com", "123-12312", "+32425255", {1, 2, 3, 4}))
        self.assertTrue(ticket1)
        ticket2 = self.service.submit_ticket(LotteryTestUtils.create_lottery_ticket("ant@bac.com", "123-12312", "+32423455", {11, 12, 13, 14}))
        self.assertTrue(ticket2)
        ticket3 = self.service.submit_ticket(LotteryTestUtils.create_lottery_ticket("arg@boo.com", "123-12312", "+32421255", {6, 8, 13, 19}))
        self.assertTrue(ticket3)
        self.assertEqual(3, len(self.administration.get_all_submitted_tickets()))

        # perform lottery
        winning_numbers = self.administration.perform_lottery()

        # cheat a bit for testing sake, use winning numbers to submit another ticket
        ticket4 = self.service.submit_ticket(LotteryTestUtils.create_lottery_ticket("lucky@orb.com", "123-12312", "+12421255", set(winning_numbers)))
        self.assertTrue(ticket4)
        self.assertEqual(4, len(self.administration.get_all_submitted_tickets()))

        # check winners
        tickets = self.administration.get_all_submitted_tickets()
        for id in tickets:
            check_result = self.service.check_ticket_for_prize(id, winning_numbers)
            assert not isinstance(check_result.result, CheckResult.TICKET_NOT_SUBMITTED)
            if check_result.result == CheckResult.WIN_PRIZE:
                self.assertGreaterEqual(check_result.prize_amount, 0)
            else:
                self.assertEqual(0, check_result.prize_amount)

        # check another ticket that has not been submitted
        check_result = self.service.check_ticket_for_prize(LotteryTicketId(), winning_numbers)
        self.assertEqual(CheckResult.TICKET_NOT_SUBMITTED, check_result.result)
        self.assertEqual(0, check_result.prize_amount)


if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the given Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.