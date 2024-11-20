import logging

class LotteryService:
    def __init__(self, repository: 'LotteryTicketRepository', notifications: 'LotteryEventLog', wire_transfers: 'WireTransfers'):
        self.repository = repository
        self.notifications = notifications
        self.wire_transfers = wire_transfers

    def submit_ticket(self, ticket: dict) -> Optional[dict]:
        player_details = ticket['player_details']
        player_account = player_details['bank_account']
        result = self.wire_transfers.transfer_funds(TICKET_PRIZE, player_account, SERVICE_BANK_ACCOUNT)
        if not result:
            self.notifications.ticket_submit_error(player_details)
            return None
        optional = self.repository.save(ticket)
        if optional is not None:
            self.notifications.ticket_submitted(player_details)
        return optional

    def check_ticket_for_prize(self, id: str, winning_numbers: dict) -> dict:
        return LotteryUtils.check_ticket_for_prize(self.repository, id, winning_numbers)

class Optional:
    @staticmethod
    def empty():
        return None

    @staticmethod
    def present(value):
        return value is not None
