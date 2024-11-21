Here is a translation of the Java code into equivalent Python code:

```Python
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
```

Please note that Python does not have direct equivalent of Java's Spring Boot and Apache Camel. This code is a translation, but it may not work exactly as the original Java code due to differences in syntax and libraries used by each language.

Also, this code assumes you are using `springboot` library which is not available for Python. You can use other frameworks like Flask or Django if needed.