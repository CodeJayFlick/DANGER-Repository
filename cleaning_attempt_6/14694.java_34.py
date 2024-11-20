class Message:
    POISON_PILL = object()

    def add_header(self, header: str, value: str) -> None:
        raise self.poison()

    def get_header(self, header: str) -> str:
        raise self.poison()

    def get_headers(self) -> dict:
        raise self.poison()

    def set_body(self, body: str) -> None:
        raise self.poison()

    def get_body(self) -> str:
        raise self.poison()

    def poison(self):
        return Exception("Poison")

class Headers(str, Enum):
    DATE = "DATE"
    SENDER = "SENDER"

add_header = lambda message, header: None
get_header = lambda message, header: ""
get_headers = lambda message: {}
set_body = lambda message, body: None
get_body = lambda message: ""

if __name__ == "__main__":
    message = Message()
    add_header(message, Headers.DATE)
    get_header(message, Headers.SENDER)
    get_headers(message)
    set_body(message, "Hello")
    get_body(message)

