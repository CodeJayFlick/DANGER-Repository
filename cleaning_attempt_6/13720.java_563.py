# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ZoomVisitor:
    def visit(self, zoom):
        pass


from abc import ABC, abstractmethod

class ModemVisitor(ABC):
    @abstractmethod
    def visit(self, modem):
        pass
