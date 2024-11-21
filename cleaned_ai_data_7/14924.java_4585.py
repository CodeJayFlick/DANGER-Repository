# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ServiceLocator:
    _services = {}

    @classmethod
    def get_service(cls, service_name):
        if service_name not in cls._services:
            # TO DO: implement logic to retrieve the service from JNDI or other source
            pass
        return cls._services[service_name]

def main():
    SERVICE_A = "jndi/serviceA"
    SERVICE_B = "jndi/serviceB"

    for _ in range(4):
        service = ServiceLocator.get_service(SERVICE_A)
        if service:
            service.execute()
        else:
            print("Service not found")

if __name__ == "__main__":
    main()

