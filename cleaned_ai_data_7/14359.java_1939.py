# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import logging

class LotteryModule:
    def configure(self):
        self.bind(LotteryTicketRepository).to(MongoTicketRepository)
        self.bind(LotteryEventLog).to(MongoEventLog)
        self.bind(WireTransfers).to(MongoBank)

# Usage example
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    lottery_module = LotteryModule()
    # configure and bind dependencies here...
