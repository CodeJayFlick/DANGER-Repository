import logging

class MeleeStrategy:
    def execute(self):
        logging.info("With your Excalibur you sever the dragon's head!")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
