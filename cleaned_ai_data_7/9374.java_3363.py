import logging

class GMouseListenerAdapter:
    LEFT = 1
    
    def __init__(self):
        self.last_mouse_button = -1
        self.did_consume = False
        self.did_popup = False

    # Client Methods
    def should_consume(self, e):
        return False

    def double_click_triggered(self, e):
        pass

    def popup_triggered(self, e):
        pass


    # MouseListener Interface Methods and Implementation
    def mouse_pressed(self, e):
        logging.debug("'pressed'")

        if e.get_consumed():
            return
        
        self.reset()  # always reset on pressed in case we never got the clicked event

        if self.consume(e):
            logging.debug("\tevent consumed")
            return
        
        if self.popup(e):
            logging.debug("\tpopup triggered")
            return


    def mouse_released(self, e):
        logging.debug("'released'")

        if e.get_consumed():
            return
        
        if self.consume(e):
            logging.debug("\tevent consumed")
            return
        
        if self.popup(e):
            logging.debug("\tpopup triggered")
            return


    def mouse_clicked(self, e):
        try:
            self.do_mouse_clicked(e)
        finally:
            self.reset()


    def do_mouse_clicked(self, e):
        logging.debug("'clicked'")

        previous_button = self.last_mouse_button
        current_button = e.get_button()
        self.last_mouse_button = current_button

        if e.get_consumed():
            return
        
        if self.consume(e) or self.did_consume:
            logging.debug("\tevent consumed on or before 'clicked'")
            return
        
        if self.popup(e) or self.did_popup:
            logging.debug("\tpopup triggered on or before 'clicked'")
            return
        
        if e.get_click_count() % 2 == 0:  # this allows double-click repeatedly without pause 
            logging.debug("\tdouble-click")
            if self.both_clicks_from_left_button(previous_button, current_button):
                logging.debug("\tdouble-clip from left")
                self.double_click_triggered(e)


    def popup(self, e):
        if e.get_popup_trigger():
            self.did_popup = True
            self.popup_triggered(e)
            return True
        return False


    def consume(self, e):
        if self.should_consume(e):
            self.did_consume = True
            e.consume()
            return True
        return False


    def both_clicks_from_left_button(self, previous_button, current_button):
        if previous_button != self.LEFT:
            return False
        
        is_left = current_button == self.LEFT
        return is_left


    def reset(self):
        self.did_consume = False
        self.did_popup = False

    logging.basicConfig(level=logging.DEBUG)
