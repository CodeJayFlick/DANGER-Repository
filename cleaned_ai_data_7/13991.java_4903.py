import logging

class RenderComponent:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def update(self):
        pass  # do nothing

    def render(self):
        self.logger.info("Render Component")
