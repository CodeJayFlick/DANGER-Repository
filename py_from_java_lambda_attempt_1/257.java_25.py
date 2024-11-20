Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
from typing import List, Collection

class DebuggerSelectMappingOfferDialog:
    def __init__(self):
        self.is_cancelled = False
        self.offer_panel = OfferPanel()
        super().__init__()

    def populate_components(self):
        self.offer_panel.border = "Select Target Recorder Mapper"
        self.add_workpanel(self.offer_panel)
        self.add_ok_button()
        self.add_cancel_button()

        # TODO: Separate this a bit
        self.offer_panel.offer_table.selection_add(0, 1)

    def set_preferred_ids(self, lang_id, cs_id):
        self.offer_panel.set_preferred_ids(lang_id, cs_id)

    def set_offers(self, offers: Collection):
        self.offer_panel.set_offers(offers)
        if len(offers) > 0:
            self.offer_panel.select_preferred()

    @property
    def is_cancelled(self):
        return self.is_cancelled

    def cancel_callback(self):
        self.is_cancelled = True
        super().cancel_callback()

    def ok_callback(self):
        selected_offer = self.offer_panel.get_selected_offer()
        if selected_offer:
            self.is_cancelled = False
            self.close()


class OfferPanel(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        self.offer_table_model = OfferTableModel()
        self.offer_table = ttk.Treeview(self, columns=self.offer_table_model.columns(), show="headings")
        for column in self.offer_table_model.columns():
            self.offer_table.heading(column, text=column)

    def set_preferred_ids(self, lang_id, cs_id):
        # TODO: Implement this
        pass

    def set_offers(self, offers: Collection):
        self.offer_table_model.clear()
        self.offer_table_model.add_all(offers)
        if len(offers) > 0:
            self.select_preferred()

    def select_preferred(self):
        for i in range(len(self.offer_table_model.model_data)):
            offer = self.offer_table_model.model_data[i]
            if (offer.get_trace_language_id() == lang_id and
                    offer.get_trace_compiler_spec_id() == cs_id):
                self.offer_table.selection_add(i)
                return

    def set_filter_recommended(self, recommended_only: bool):
        # TODO: Implement this
        pass


class OfferTableModel:
    def __init__(self):
        super().__init__()
        self.columns = ["Offers"]

    def default_sort_order(self) -> List[OfferTableColumns]:
        return [OfferTableColumns.CONFIDENCE, OfferTableColumns.PROCESSOR,
                OfferTableColumns.VARIANT, OfferTableColumns.COMPILER]


class OfferTableColumns:
    CONFIDENCE = "Confidence"
    PROCESSOR = "Processor"
    VARIANT = "Variant"
    SIZE = "Size"
    ENDIAN = "Endian"
    COMPILER = "Compiler"

    def __init__(self):
        pass


if __name__ == "__main__":
    dialog = DebuggerSelectMappingOfferDialog()
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The `GhidraTable`, `GhidraTableFilterPanel`, `LanguageID`, `CompilerSpecID` classes are missing in the provided Java code, so I left them out from the Python version as well.