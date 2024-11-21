import logging
from properties import Properties  # Assuming you have a 'properties' module with a class named 'Properties'

class App:
    PROP_FILE_NAME = "config.properties"
    interactive_mode = False

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def main(args=None):
        app = App()
        app.set_up()
        app.run()

    def set_up(self):
        prop = Properties()
        input_stream = None
        try:
            input_stream = open(App.PROP_FILE_NAME, 'r')
            prop.load(input_stream)
        except Exception as e:
            self.logger.error(f"{App.PROP_FILE_NAME} was not found. Defaulting to non-interactive mode.")
        property = prop.get("INTERACTIVE_MODE")
        if property.lower() == "yes":
            App.interactive_mode = True

    def run(self):
        if App.interactive_mode:
            self.run_interactive()
        else:
            self.quick_run()

    def quick_run(self):
        event_manager = EventManager()
        try:
            # Create an Asynchronous event.
            async_event_id = event_manager.create_async(60)
            print(f"Async Event [{async_event_id}] has been created.")
            event_manager.start(async_event_id)
            print(f"Async Event [{async_event_id}] has been started.")

            # Create a Synchronous event.
            sync_event_id = event_manager.create(60)
            print(f"Sync Event [{sync_event_id}] has been created.")
            event_manager.start(sync_event_id)
            print(f"Sync Event [{sync_event_id}] has been started.")

            event_manager.status(async_event_id)
            event_manager.status(sync_event_id)

            event_manager.cancel(async_event_id)
            print(f"Async Event [{async_event_id}] has been stopped.")
            event_manager.cancel(sync_event_id)
            print(f"Sync Event [{sync_event_id}] has been stopped.")
        except Exception as e:
            self.logger.error(str(e))

    def run_interactive(self):
        s = input()
        option = -1
        while option != 4:
            print("Hello. Would you like to boil some eggs?")
            print("(1) BOIL AN EGG \n(2) STOP BOILING THIS EGG \n(3) HOW ARE MY EGGS? \n(4) EXIT")
            print("Choose [1,2,3,4]: ")
            option = int(s)
            if option == 1:
                self.process_option_1(event_manager=s)
            elif option == 2:
                self.process_option_2(event_manager=event_manager, s=s)
            elif option == 3:
                self.process_option_3(event_manager=event_manager, s=s)
            elif option == 4:
                event_manager.shutdown()
        s.close()

    def process_option_1(self, event_manager):
        print("Just one egg (O) OR all of them (A) ?: ")
        egg_choice = input()
        if egg_choice.lower() == "o":
            print("Which egg?: ")
            eventId = int(input())
            try:
                event_manager.status(eventId)
            except Exception as e:
                self.logger.error(str(e))
        elif egg_choice.lower() == "a":
            event_manager.status_of_all_events()

    def process_option_2(self, event_manager):
        print("Which egg?: ")
        eventId = int(input())
        try:
            event_manager.cancel(eventId)
            print(f"Egg [{eventId}] is removed from boiler.")
        except Exception as e:
            self.logger.error(str(e))

    def process_option_3(self, event_manager):
        s = input()
        if s.lower() == "o":
            print("Which egg?: ")
            eventId = int(input())
            try:
                event_manager.status(eventId)
            except Exception as e:
                self.logger.error(str(e))
        elif s.lower() == "a":
            event_manager.status_of_all_events()

if __name__ == "__main__":
    App.main()
