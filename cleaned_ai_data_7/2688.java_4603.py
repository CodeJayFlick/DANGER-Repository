import tkinter as tk
from tkinter import ttk

class GLifespanField:
    NEG_INF = "-∞"
    POS_INF = "+∞"

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("GLifespan Field")
        
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        self.label_lower = ttk.Label(main_frame, text="[")
        self.label_lower.pack(side=tk.LEFT)

        self.field_min = ttk.Combobox(main_frame, state='readonly')
        self.field_min.set_values([self.NEG_INF])
        self.field_min.pack(side=tk.LEFT)
        
        tk.Frame(self.root).pack(fill="x")

        self.label_upper = ttk.Label(main_frame, text="]")
        self.label_upper.pack(side=tk.RIGHT)

        self.field_max = ttk.Combobox(main_frame, state='readonly')
        self.field_max.set_values([self.POS_INF])
        self.field_max.pack(side=tk.RIGHT)
        
    def parse_long(self, text, default_val):
        try:
            return int(text)
        except ValueError:
            return default_val

    def revalidate_min(self):
        value = self.field_min.get()
        if value == self.NEG_INF:
            self.label_lower.config(text "(")
        else:
            self.field_min.set(value=str(self.parse_long(value, 0)))
            self.label_lower.config(text "[")

    def revalidate_max(self):
        value = self.field_max.get()
        if value == self.POS-INF:
            self.label_upper.config(text ")")
        else:
            self.field_max.set(value=str(self.parse_long(value, 0)))
            self.label_upper.config(text "]")

    def adjust_max_to_min(self):
        if not self.is_unbounded():
            min_val = int(self.field_min.get() or "0")
            max_val = max(min_val, int(self.field_max.get() or str(min_val)))
            self.field_max.set(str(max_val))

    def is_unbounded(self):
        return self.NEG_INF == self.field_min.get() or self.POS_INF == self.field_max.get()

    def adjust_min_to_max(self):
        if not self.is_unbounded():
            max_val = int(self.field_max.get() or "0")
            min_val = min(max_val, int(self.field_min.get() or str(max_val)))
            self.field_min.set(str(min_val))

    def min_focus_lost(self, e):
        self.revalidate_min()
        self.adjust_max_to_min()

    def max_focus_lost(self, e):
        self.revalidate_max()
        self.adjust_min_to_max()

    def set_lifespan(self, lifespan):
        if not lifespan.is_bounded() or (lifespan.has_lower_bound() and lifespan.lower_bound_type == "open" or 
                                          lifespan.has_upper_bound() and lifespan.upper_bound_type == "open"):
            raise ValueError("Lifespans must be closed or unbounded")

        if not lifespan.has_lower_bound():
            self.field_min.set(self.NEG_INF)
        else:
            self.field_min.set(str(lifespan.lower_endpoint()))

        if not lifespan.has_upper_bound():
            self.field_max.set(self.POS_INF)
        else:
            self.field_max.set(str(lifespan.upper_endpoint()))

    def get_lifespan(self):
        min_val = int(self.field_min.get() or "0")
        max_val = int(self.field_max.get() or str(min_val))

        if self.NEG_INF == self.field_min.get():
            if self.POS_INF == self.field_max.get():
                return range(-float('inf'), float('inf'))
            else:
                return range(0, max_val + 1)
        elif self.POS_INF == self.field_max.get():
            return range(min_val, float('inf'))
        else:
            return range(min_val, max_val + 1)

    def set_enabled(self, enabled):
        self.root.config(state='normal' if enabled else 'disabled')
        self.field_min.config(state='normal' if enabled else 'disabled')
        self.field_max.config(state='normal' if enabled else 'disabled')

if __name__ == "__main__":
    app = GLifespanField()
