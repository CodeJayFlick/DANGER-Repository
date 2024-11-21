# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import inject

class LotteryTestingModule:
    def configure(self):
        self.bind(LotteryTicketRepository).to(InMemoryTicketRepository)
        self.bind(LotteryEventLog).to(StdOutEventLog)
        self.bind(WireTransfers).to(InMemoryBank)

LotteryTicketRepository = object
InMemoryTicketRepository = object

LotteryEventLog = object
StdOutEventLog = object

WireTransfers = object
InMemoryBank = object
