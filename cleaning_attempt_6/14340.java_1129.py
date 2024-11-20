# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import injector
from lottery_administration import LotteryAdministration
from lottery_service import LotteryService
from testing_module import LotteryTestingModule
from sample_data import SampleData

class App:
    def main(self):
        injector = injector.Injector(LotteryTestingModule())
        
        # start new lottery round
        administration = injector.get(LotteryAdministration)
        administration.reset_lottery()

        # submit some lottery tickets
        service = injector.get(LotteryService)
        SampleData.submit_tickets(service, 20)

        # perform lottery
        administration.perform_lottery()


if __name__ == "__main__":
    App().main()
