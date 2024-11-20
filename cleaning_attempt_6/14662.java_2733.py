class Page:
    AUT_PATH = "src/main/resources/sample-ui/"

    def __init__(self, web_client):
        self.web_client = web_client

    @abstractmethod
    def is_at(self) -> bool:
        pass


# Example usage:
from htmlunit import WebClient

web_client = WebClient()
page = Page(web_client)
