import logging
from springboot import SpringApplicationBuilder

class App:
    def __init__(self):
        self.app = SpringApplicationBuilder().main(__name__).run()

    @staticmethod
    def main(args=None):
        app = App()
        context = app.app.getApplication().getBean("camelContext")

        route_builder = RouteBuilder()
        route_builder.configure()
        from_ = "endpoint"
        to_log = f"ENDPOINT: {context}"
        route_builder.route(from_, to_log)

        string_array = ["Test item #1", "Test item #2", "Test item #3"]
        context.create_producer_template().send_body("entry", *string_array)
