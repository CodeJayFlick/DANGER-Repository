import logging

class EventObserver:
    def on_event(self, event):
        logging.info("Received event from the King's Hand: {}".format(event))

if __name__ == "__main__":
    class KingJoffrey(EventObserver):
        pass

    king_joffrey = KingJoffrey()
    # You would use this object to observe events
