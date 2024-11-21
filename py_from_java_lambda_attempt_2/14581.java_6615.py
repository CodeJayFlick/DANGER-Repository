Here is the translation of the given Java code into Python:

```Python
class LoadBalancer:
    def __init__(self):
        self.servers = []
        self.last_served_id = 0

    def add_server(self, server):
        self.servers.append(server)

    def get_no_of_servers(self):
        return len(self.servers)

    def last_served_id(self):
        return self.last_served_id

    def serve_request(self, request):
        pass


class Server:
    def __init__(self, host, port, capacity):
        self.host = host
        self.port = port
        self.capacity = capacity

    def get_host(self):
        return self.host

    def get_port(self):
        return self.port

    def serve_request(self, request):
        pass


import unittest

class TestLoadBalancer(unittest.TestCase):

    def test_same_state_amongst_all_instances(self):
        first_balancer = LoadBalancer()
        second_balancer = LoadBalancer()

        server1 = Server("localhost", 8085, 6)
        first_balancer.add_server(server1)

        self.assertEqual(first_balancer.get_no_of_servers(), second_balancer.get_no_of_servers())
        self.assertEqual(first_balancer.last_served_id(), second_balancer.last_served_id())

    def test_serve(self):
        server = Server("testhost", 1234, 6)
        load_balancer = LoadBalancer()

        load_balancer.add_server(server)

        for _ in range(2 * load_balancer.get_no_of_servers()):
            load_balancer.serve_request(Request("test"))

    def test_serve_request(self):
        pass


if __name__ == '__main__':
    unittest.main()
```

Please note that the `Request` class is not defined in your original Java code, so I left it as a placeholder. You would need to define this class or replace its usage with something else depending on what you're trying to achieve.