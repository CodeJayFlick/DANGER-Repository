Here is the translation of the Java code to Python:
```
import logging

class ServiceCache:
    def __init__(self):
        self.service_cache = {}

    def get_service(self, service_name: str) -> dict or None:
        if service_name in self.service_cache:
            cached_service = self.service_cache[service_name]
            logging.info("(cache call) Fetched service {}({}) from cache... !".format(cached_service['name'], cached_service['id']))
            return cached_service
        return None

    def add_service(self, new_service: dict):
        self.service_cache[new_service['name']] = new_service


# Example usage:
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    service_cache = ServiceCache()

    # Add some services to the cache
    service1 = {'id': 1, 'name': 'Service A'}
    service2 = {'id': 2, 'name': 'Service B'}

    service_cache.add_service(service1)
    service_cache.add_service(service2)

    # Get a service from the cache
    service_name = 'Service A'
    cached_service = service_cache.get_service(service_name)
    if cached_service:
        print("Fetched {}({}) from cache!".format(cached_service['name'], cached_service['id']))
```
Note that I used Python's built-in `logging` module to implement the logging functionality, and replaced Java's `HashMap` with a simple dictionary (`{}`) in Python.