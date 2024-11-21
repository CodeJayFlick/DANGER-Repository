Here is the translation of the given Java code into Python:

```Python
class Ambassador:
    def __init__(self):
        pass

    def use_service(self, service_id):
        print(f"Using Service {service_id}")

class Client:
    def __init__(self):
        self.ambassador = Ambassador()

    def use_service(self, service_id):
        self.ambassador.use_service(service_id)

def main():
    host1 = Client()
    host2 = Client()
    host1.use_service(12)
    host2.use_service(73)

if __name__ == "__main__":
    main()
```

Please note that this is a direct translation of the given Java code into Python. The original intent and functionality might not be exactly preserved, as some design patterns or language-specific constructs may have been lost in translation.