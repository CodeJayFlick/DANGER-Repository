class LotteryAdministration:
    def __init__(self, repository: 'LotteryTicketRepository', notifications: 'LotteryEventLog', wire_transfers: 'WireTransfers'):
        self.repository = repository
        self.notifications = notifications
        self.wire_transfers = wire_transfers

    def get_all_submitted_tickets(self) -> dict:
        return self.repository.find_all()

    def perform_lottery(self):
        numbers = LotteryNumbers.create_random()
        tickets = self.get_all_submitted_tickets()
        for id in tickets.keys():
            lottery_ticket = tickets[id]
            player_details = lottery_ticket.player_details
            player_account = player_details.bank_account
            result = LotteryUtils.check_ticket_for_prize(self.repository, id, numbers).result
            if result == LotteryTicketCheckResult.CHECK_RESULT_WIN_PRIZE:
                if self.wire_transfers.transfer_funds(LotteryConstants.PRIZE_AMOUNT, LotteryConstants.SERVICE_BANK_ACCOUNT, player_account):
                    self.notifications.ticket_won(player_details, LotteryConstants.PRIZE_AMOUNT)
                else:
                    self.notifications.prize_error(player_details, LotteryConstants.PRIZE_AMOUNT)
            elif result == LotteryTicketCheckResult.CHECK_RESULT_NO_PRIZE:
                self.notifications.ticket_did_not_win(player_details)

        return numbers

    def reset_lottery(self):
        self.repository.delete_all()
