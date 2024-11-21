# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import abc

class OrderService(metaclass=abc.ABCMeta):
    def __init__(self, service_discovery_service):
        pass

    @property
    def name(self):
        return "Init an order"
