import logging

class ConfigureForUnixVisitor:
    def visit(self, zoom):
        logging.info(f"{zoom} used with Unix configurator.")

if __name__ == "__main__":
    # Example usage
    visitor = ConfigureForUnixVisitor()
    zoom = "Some Zoom"
    visitor.visit(zoom)
