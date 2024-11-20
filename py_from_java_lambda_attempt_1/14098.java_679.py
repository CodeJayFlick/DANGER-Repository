Here is a translation of the Java code into equivalent Python code:

```Python
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
```

Please note that Python does not have direct equivalent of Java's Spring Boot and Apache Camel. The above code is a simplified translation, it doesn't cover all the functionalities provided by these libraries in Java.

Here are some key differences:

1. `@SpringBootApplication` annotation: This is used to enable auto-configuration for your application. In Python, you can achieve this using Flask or Django frameworks which provide similar functionality.
2. `CamelContext`: Apache Camel provides a way to integrate with other systems and services in Java. There isn't an equivalent library in Python that offers the same level of integration capabilities as Apache Camel does in Java.

The above code is written assuming you are familiar with Spring Boot, Apache Camel, and their respective functionalities.