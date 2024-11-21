Here is the translation of the given Java code into Python:

```Python
class RecorderComposedRegisterSet:
    def __init__(self, recorder):
        self.recorder = recorder

    def registerAccessibilityChanged(self, old, acc, _):
        self.recorder.getListeners().fire_registerAccessibilityChanged(self.recorder)

    def fetchRegAccessibility(self, bank):
        return DebugModelConventions.track_accessibility(bank).then_apply(lambda acc: 
            (acc.addChangeListener(self.registerAccessibilityChanged), acc))

    @property
    def accessibilityByRegBank(self):
        if not hasattr(self, '_accessibility_by_reg_bank'):
            self._accessibility_by_reg_bank = AsyncLazyMap(HashMap(), self.fetchRegAccessibility)
        return self._accessibility_by_reg_bank

    def remove(self, key):
        acc = super().remove(key)
        if acc is not None:
            acc.removeChangeListener(self.registerAccessibilityChanged)
        return acc

    def update_registers(self, new_regs, old_regs):
        with self.accessibilityByRegBank as map:
            if old_regs is not None:
                map.remove(old_regs)
            try:
                result = map.get(new_regs).get()
            except Exception as e:
                Msg.error(self, f"Could not track register accessibility: {e}")
                return
            else:
                return

    def check_registers_removed(self, regs, invalid):
        with self.accessibilityByRegBank as map:
            if (regs.values().remove(invalid)):
                map.remove((invalid))
                return True
            return False

    def is_register_bank_accessible(self, bank):
        if bank is None:
            return False
        try:
            future = self.accessibilityByRegBank.get(bank)
            acc = future.get_now(None)
            if acc is None:
                return False
            else:
                return acc.get()
        except Exception as e:
            return False

class AsyncLazyMap(dict):
    def __init__(self, d=None, fetch_func=lambda k: None):
        super().__init__()
        self.fetch_func = fetch_func
        if d:
            for key in d:
                self[key] = d[key]

    def get(self, key):
        value = dict.get(self, key)
        if value is not None:
            return value

        try:
            value = self.fetch_func(key).get()
            super().__setitem__(key, value)
            return value
        except Exception as e:
            Msg.error(None, f"Could not track register accessibility: {e}")
            return None

    def remove(self, key):
        if key in self:
            del self[key]
```

Note that Python does not have direct equivalents for Java's `CompletableFuture` and `AsyncLazyMap`. The above code uses a simple dictionary to simulate the behavior of these classes.