import logging
from springboot import SpringApplicationBuilder

class App:
    def __init__(self):
        self.application = SpringApplicationBuilder(App).run()

    @staticmethod
    def main(args=None):
        context = SpringApplicationBuilder(App).run()
        camel_context = context.get('camelContext')

        route_builder = RouteBuilder()
        route_builder.configure(
            from_("{{endpoint}}").log(logging.INFO, "ENDPOINT: %s", "${body}"),
            from_("{{wireTapEndpoint}}").log(logging.INFO, "WIRETAPPED ENDPOINT: %s", "${body}")
        )

        camel_context.add_routes(route_builder)

        producer_template = camel_context.create_producer_template()
        producer_template.send_body("{{entry}}", "Test message")

    def exit(self):
        self.application.exit()

if __name__ == "__main__":
    App().main()
