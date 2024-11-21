import logging
from typing import Any

logging.basicConfig(level=logging.INFO)

class ConsoleAdministration:
    def __init__(self):
        self.administration = None
        self.service = None
        self.console_administration = None

    def main(self) -> None:
        MongoConnectionPropertiesLoader.load()
        injector = Guice.createInjector(LotteryModule())
        self.administration = injector.getInstance(LotteryAdministration)
        self.service = injector.getInstance(LotteryService)
        SampleData.submit_tickets(self.service, 20)
        self.console_administration = ConsoleAdministrationSrvImpl(
            self.administration,
            logging.getLogger()
        )
        try:
            scanner = input()
            exit = False
            while not exit:
                print_menu()
                cmd = read_string(scanner)
                if cmd == "1":
                    self.console_administration.get_all_submitted_tickets()
                elif cmd == "2":
                    self.console_administration.perform_lottery()
                elif cmd == "3":
                    self.console_administration.reset_lottery()
                elif cmd == "4":
                    exit = True
                else:
                    logging.info(f"Unknown command: {cmd}")
        except Exception as e:
            logging.error(str(e))

    def print_menu(self) -> None:
        logging.info("")
        logging.info("### Lottery Administration Console ###")
        logging.info("(1) Show all submitted tickets")
        logging.info("(2) Perform lottery draw")
        logging.info("(3) Reset lottery ticket database")
        logging.info("(4) Exit")

    def read_string(self, scanner: Any) -> str:
        logging.info("> ")
        return input()

if __name__ == "__main__":
    administration = ConsoleAdministration()
    administration.main()
