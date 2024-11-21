from tkinter import *
import threading

class AddressInput:
    def __init__(self):
        self.addr_factory = None
        self.change_listener = None
        self.updating_address = False
        self.update_space_field = False
        self.state_changing = False
        self.space_field = None
        
        self.root = Tk()
        self.root.title("Address Input")
        
        self.text_field = Entry(self.root, width=10)
        self.combo_box = ttk.Combobox(self.root)

    def set_address_factory(self, factory):
        if not isinstance(factory, AddressFactory):
            raise TypeError('factory must be an instance of AddressFactory')
        self.addr_factory = factory
        address_spaces = factory.get_address_spaces()
        
        sorted_spaces = sorted(address_spaces)
        for space in sorted_spaces:
            self.combo_box.insert(END, str(space))
            
    def set_address(self, addr):
        if not isinstance(addr, Address):
            raise TypeError('addr must be an instance of Address')
        if self.state_changing:
            return
        self.updating_address = True
        
        text_field_text = str(addr)
        combo_box_selected_item = addr.get_address_space()
        
        self.text_field.delete(0, END)
        self.text_field.insert(0, text_field_text)
        self.combo_box.set(combo_box_selected_item.name if combo_box_selected_item else '')
        
        self.updating_address = False
        if self.update_space_field:
            self.space_field.config(text=str(combo_box_selected_item))
    
    def get_address(self):
        addr_str = str(self.text_field.get())
        try:
            return self.addr_factory.create_address(addr_str)
        except AddressFormatException as e:
            return None
    
    def has_input(self):
        return len(str(self.text_field.get())) > 0

    def set_editable(self, state):
        if not isinstance(state, bool):
            raise TypeError('state must be a boolean')
        self.text_field.config(state=state)
    
    def is_enabled(self):
        return self.root.winfo_ismapped()
    
    def add_change_listener(self, listener):
        if not callable(listener):
            raise TypeError('listener must be a function')
        self.change_listener = listener
    
    def remove_action_listener(self, listener):
        pass  # Not implemented in Python
        #if hasattr(self.text_field, 'remove_command'):
        #    self.text_field.remove_command(listener)
    
    def set_address_space_editable(self, state):
        if not isinstance(state, bool):
            raise TypeError('state must be a boolean')
        
        combo_box_selected_item = str(self.combo_box.get())
        space_name = f"{combo_box_selected_item}:" if combo_box_selected_item else "          "
        self.space_field.config(text=space_name)
    
    def show_address_space_combo(self, state):
        if not isinstance(state, bool):
            raise TypeError('state must be a boolean')
        
        if state:
            if not hasattr(self, 'combo_box'):
                self.combo_box.pack(side='left', fill='x')
            else:
                self.combo_box.update_idletasks()
        else:
            if hasattr(self, 'space_field'):
                self.space_field.destroy()
    
    def request_focus(self):
        self.text_field.focus_set()

class AddressFactory:
    pass

class AddressFormatException(Exception):
    pass
