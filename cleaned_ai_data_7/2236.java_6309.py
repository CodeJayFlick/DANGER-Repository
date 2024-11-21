from abc import ABCMeta, abstractmethod
import collections as col
import concurrent.futures as fut

class AbstractTestTargetRegisterBank(metaclass=ABCMeta):
    def __init__(self, parent, name, type_hint, regs):
        self.regs = regs
        self.reg_vals = {}

    @abstractmethod
    def get_thread(self):
        pass

    def read_registers_named(self, names):
        if not set(names).issubset(set(self.regs.get_descs().keys())):
            raise DebuggerRegisterAccessException("No such register")
        
        result = {}
        for n in names:
            v = self.reg_vals.get(n)
            if v is None:
                v = self.regs.get_descs()[n].default_value
            result[n] = v
        
        return fut.as_completed([self.model.gate_future(self.regs.model.future(result).then_run(lambda x: [self.listeners.fire_registers_updated(self, result)]))])

    def write_regs(self, values, set_pc):
        if not set(values.keys()).issubset(set(self.regs.get_descs().keys())):
            raise DebuggerRegisterAccessException("No such register")
        
        updates = {}
        future = self.regs.model.future(None)
        for ent in values.items():
            n = ent[0]
            desc = self.regs.get_descs()[n]
            v = desc.normalize_value(ent[1])
            self.reg_vals[n] = v
            updates[n] = v
            if desc.is_pc:
                future.then_run(lambda x: set_pc(desc.parse_address(v)))
        
        future.then_run(lambda x: [self.listeners.fire_registers_updated(self, updates)])
        return fut.as_completed([future])

    def set_from_bank(self, bank):
        self.reg_vals.update(bank.reg_vals)
        for key in list(self.reg_vals.keys()):
            if not bank.reg_vals.get(key):
                del self.reg_vals[key]
