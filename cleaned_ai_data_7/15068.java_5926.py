import logging

class SubtleMethod:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def pick_target(self) -> str:
        return "shop keeper"

    def confuse_target(self, target: str) -> None:
        self.logger.info("Approach the {} with tears running and hug him!", target)

    def steal_the_item(self, target: str) -> None:
        self.logger.info("While in close contact grab the {}'s wallet.", target)
