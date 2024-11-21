import logging

class App:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    @staticmethod
    def main():
        app = App()
        app.use_of_logged_mute()
        app.use_of_mute()

    def use_of_mute(self):
        out = bytearray()
        Mute().mute(lambda: out.extend(b"Hello"))

    def use_of_logged_mute(self):
        resource = None
        try:
            resource = acquire_resource()
            utilize_resource(resource)
        finally:
            if resource is not None:
                close_resource(resource)

    @staticmethod
    def close_resource(resource):
        Mute().logged_mute(lambda: resource.close())

    @staticmethod
    def utilize_resource(resource):
        print(f"Utilizing acquired resource: {resource}")

    @staticmethod
    def acquire_resource():
        return Resource()

class Resource:
    def __init__(self):
        pass

    def close(self):
        raise IOError("Error in closing resource")

if __name__ == "__main__":
    App.main()
