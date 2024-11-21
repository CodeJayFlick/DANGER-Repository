import logging

class AbstractAnimatorJob:
    TOO_BIG_TO_ANIMATE = 125

    def __init__(self):
        self.log = logging.getLogger(__name__)
        self.is_finished = False
        self.busy_listener = None
        self.animator = None
        self.is_shortcut = False
        self.finished_listener = None

    def create_animator(self):
        # This method should be implemented in the subclass.
        pass

    def finished(self):
        # This method should be implemented in the subclass.
        pass

    def set_busy_listener(self, listener):
        self.busy_listener = listener

    @property
    def is_finished(self):
        return self._is_finished

    @is_finished.setter
    def is_finished(self, value):
        if not isinstance(value, bool):
            raise TypeError("is_finished must be a boolean")
        self._is_finished = value

    def can_shortcut(self):
        return True

    def shortcut(self):
        self.log.info(f"shortcut(): {self}")
        self.is_shortcut = True
        self.stop()

    def execute(self, listener):
        self.finished_listener = listener
        self.start()

    @property
    def is_shortcut(self):
        return self._is_shortcut

    @is_shortcut.setter
    def is_shortcut(self, value):
        if not isinstance(value, bool):
            raise TypeError("is_shortcut must be a boolean")
        self._is_shortcut = value

    def dispose(self):
        self.log.info(f"dispose(): {self}")
        self.stop()

    @property
    def animator(self):
        return self._animator

    @animator.setter
    def animator(self, value):
        if not isinstance(value, Animator):
            raise TypeError("animator must be an instance of Animator")
        self._animator = value

    def start(self):
        self.log.info(f"start() - {self.__class__.__name__}")

        try:
            self.animator = self.create_animator()
        except Exception as e:
            self.log.error(f"Unexpected exception creating animator: {e}")
            self.emergency_finish()

        if self.animator is None:
            self.call_finish()
            return

        if self.busy_listener is not None:
            self.animator.add_target(TimingTargetAdapter(self.busy_listener))

        self.animator.add_target(TimingTargetAdapter(lambda: self.call_finish()))
        self.animator.start()

    def call_finish(self):
        self.log.info("callFinish()")

        if self.is_finished:
            self.log.info("\talready finished")
            return  # already called

        try:
            self.finished()
        except Exception as e:
            self.log.error(f"Unexpected error in AbstractAnimator: {e}")

        self.is_finished = True

        if self.finished_listener is not None:
            self.log.info("\tmaybe notify finished...")
            self.finished_listener.job_finished(self)

        if self.busy_listener is not None:
            self.busy_listener.set_busy(False)

    def emergency_finish(self):
        self.log.info("emergencyFinish()")

        if self.is_finished:
            self.log.info("\talready finished")
            return  # already called

        self.is_finished = True

        if self.finished_listener is not None:
            self.log.info("\tmaybe notify finished...")
            self.finished_listener.job_finished(self)

        if self.busy_listener is not None:
            self.busy_listener.set_busy(False)

    def stop(self):
        self.log.info("stop()")

        if self.animator is None:
            self.call_finish()
            return

        self.animator.stop()

    def __str__(self):
        return f"{self.__class__.__name__}"
