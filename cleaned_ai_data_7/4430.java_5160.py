import tkinter as tk
from typing import List, Tuple

class DbViewerComponent:
    def __init__(self):
        self.dbh = None
        self.tables = []
        self.table_stats = {}
        self.update_mgr = None
        self.south_panel = None
        self.combo = None
        self.db_label = None
        
        root = tk.Tk()
        frame = tk.Frame(root)
        frame.pack()

        north_panel = tk.Frame(frame, bg='gray')
        sub_north_panel = tk.Frame(north_panel)

        db_label = tk.Label(sub_north_panel, text="")
        combo = tk.OptionMenu(sub_north_panel, self.combo, *self.tables)

        sub_north_panel.pack(side=tk.LEFT)
        north_panel.pack()

    def close_database(self):
        if self.dbh:
            self.combo['menu'].delete(0, 'end')
            self.db_label.config(text="")
            if self.south_panel:
                self.south_panel.destroy()
                self.south_panel = None
            self.tables.clear()
            self.table_stats.clear()
            self.dbh = None

    def open_database(self, name: str, handle):
        self.close_database()

        self.dbh = handle
        self.db_label.config(text=name)
        self.update_table_choices(None)

        listener = InternalDBListener(handle)
        handle.add_listener(listener)

    def refresh(self):
        if not self.dbh:
            return

        stats = []
        for table in self.tables:
            try:
                stat = get_stats(table)
                stats.append(stat[0])
            except Exception as e:
                print(f"Unexpected exception: {e}")

        self.update_table_choices(None)

    def refresh_table(self):
        if not self.dbh:
            return

        t = combo.get()
        if t:
            panel = create_south_panel(t)
            frame.add(panel, tk.TOP)
            revalidate()

    def dispose(self):
        update_mgr.dispose()
        close_database()

def get_stats(table: Table) -> Tuple[TableStatistics]:
    stats = self.table_stats[table.name]
    for i in range(2, len(stats)):
        # combine index stats
        stats[1].buffer_count += stats[i].buffer_count
        stats[1].chained_buffer_cnt += stats[i].chained_buffer_cnt
        stats[1].interior_node_cnt += stats[i].interior_node_cnt
        stats[1].record_node_cnt += stats[i].record_node_cnt
    return stats

def update_table_choices(self, selected_table):
    self.tables = []
    combo['menu'].delete(0, 'end')
    table_stats.clear()

    if self.dbh:
        for i in range(len(self.dbh.get_tables())):
            self.tables.append(new TableItem(self.dbh.get_tables()[i]))
        combosort.sort(self.tables)

    sel_index = -1
    for i in range(len(self.tables)):
        combo['menu'].add_command(label=self.tables[i].name, command=tk._setit(combo, self.tables[i]))

    if selected_table:
        for i in range(len(self.tables)):
            if self.tables[i].name == selected_table.name:
                sel_index = i
                break

    if sel_index >= 0:
        combo.set_active(sel_index)

def update_table(self):
    panel.destroy()
    panel = create_south_panel(t)
    frame.add(panel, tk.TOP)
    revalidate()

class TableItem:
    def __init__(self, table: Table):
        self.table = table
        self.name = table.get_name()

    def __str__(self) -> str:
        return f"{self.name} ({self.table.get_record_count()})"

class InternalDBListener:
    def db_closed(self, handle):
        if handle == DbViewerComponent.this.dbh:
            close_database()

    def db_restored(self, handle):
        if handle == DbViewerComponent.this.dbh:
            update_mgr.update_later()

    def table_added(self, handle: DBHandle, table: Table):
        if handle == DbViewerComponent.this.dbh:
            update_mgr.update_later()

    def table_deleted(self, handle: DBHandle, table: Table):
        if handle == DbViewerComponent.this.dbh:
            update_mgr.update_later()
