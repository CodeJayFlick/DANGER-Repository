import logging
from threading import Thread
import time
import random

class GameStatus:
    STOPPED = 0
    RUNNING = 1


class GameController:
    def __init__(self):
        pass

    def get_bullet_position(self):
        # simulate getting bullet position from game controller
        return "bullet position"


class GameLoop:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.status = GameStatus.STOPPED
        self.controller = GameController()
        self.game_thread = None

    def run(self):
        self.status = GameStatus.RUNNING
        self.game_thread = Thread(target=self.process_game_loop)
        self.game_thread.start()

    def stop(self):
        self.status = GameStatus.STOPPED

    def is_game_running(self):
        return self.status == GameStatus.RUNNING


    def process_input(self):
        lag = random.randint(50, 250) * 1000
        time.sleep(lag / 1000)

    def render(self):
        position = self.controller.get_bullet_position()
        self.logger.info(f"Current bullet position: {position}")

    def process_game_loop(self):
        while True:
            if not self.is_game_running():
                break

            self.process_input()
            self.render()


if __name__ == "__main__":
    game_loop = GameLoop()
