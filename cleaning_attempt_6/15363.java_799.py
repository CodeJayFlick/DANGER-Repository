class CustomDefaultTimeBar:
    def __init__(self):
        self.scrubber_bar = None
        self.scrubbing = False
        self.scrubbing_start_x = 0

    def onTouchEvent(self, event):
        if event.get_action() == MotionEvent.ACTION_DOWN and self.scrubber_bar is not None:
            self.scrubbing = False
            self.scrubbing_start_x = int(event.get_x())
            distance_from_scrubber = abs(int(self.scrubber_bar.right) - self.scrubbing_start_x)
            if distance_from_scrubber > 24: 
                return True
            else:
                self.scrubbing = True

        elif not self.scrubbing and event.get_action() == MotionEvent.ACTION_MOVE and self.scrubber_bar is not None:
            distance_from_start = abs(int(event.get_x()) - self.scrubbing_start_x)
            if distance_from_start > 6: 
                self.scrubbing = True
                try:
                    method = DefaultTimeBar.startScrubbing(0) # equivalent to Java's invoke() method
                except Exception as e:
                    print(e)

            else:
                return True

        return super.onTouchEvent(event)
