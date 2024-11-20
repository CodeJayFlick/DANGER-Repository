Here is the translation of the Java code to Python:
```
class GroupByTimePlan:
    def __init__(self):
        self.startTime = None
        self.endTime = None
        self.interval = None
        self.sliding_step = None
        self.is_interval_by_month = False
        self.is_sliding_step_by_month = False
        self.left_c_right_o = True

    @property
    def start_time(self):
        return self.startTime

    @start_time.setter
    def set_start_time(self, value):
        self.startTime = value

    @property
    def end_time(self):
        return self.endTime

    @end_time.setter
    def set_end_time(self, value):
        self.endTime = value

    @property
    def interval(self):
        return self.interval

    @interval.setter
    def setInterval(self, value):
        self.interval = value

    @property
    def is_sliding_step_by_month(self):
        return self.is_sliding_step_by_month

    @is_sliding_step_by_month.setter
    def setSlidingStepByMonth(self, value):
        self.is_sliding_step_by_month = value

    @property
    def is_interval_by_month(self):
        return self.is_interval_by_month

    @is_interval_by_month.setter
    def setIntervalByMonth(self, value):
        self.is_interval_by_month = value

    @property
    def sliding_step(self):
        return self.sliding_step

    @sliding_step.setter
    def setSlidingStep(self, value):
        self.sliding_step = value

    @property
    def left_c_right_o(self):
        return self.left_c_right_o

    @left_c_right_o.setter
    def setLeftCRightO(self, value):
        self.left_c_right_o = value
```
Note that I used Python's built-in property decorator to create getter and setter methods for each attribute. This is a common pattern in Python programming.