import logging

class App:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.context = None

    def main(self):
        import camelcamelcamel  # Apache Camel for Python (not actual library)
        from stream import StreamIn, StreamOut

        try:
            self.context = camelcamelcamel.CamelContext()
            route_builder = RouteBuilder()

            @route_builder.configure
            def configure():
                route_builder.from_(StreamIn()).to_("direct:greetings")
                route_builder.from_("direct:greetings").to_(StreamOut())

            self.context.add_routes(route_builder)
            self.context.start()
            for r in self.context.get_routes():
                self.logger.info(str(r))
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.context is not None:
                try:
                    self.context.stop()
                except Exception as e:
                    print(f"Error stopping context: {e}")

if __name__ == "__main__":
    app = App()
    app.main()

