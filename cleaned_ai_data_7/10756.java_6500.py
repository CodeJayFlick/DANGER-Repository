import queue
from threading import Thread

class GraphJobRunner:
    def __init__(self):
        self.queue = queue.Queue()
        self.final_job = None
        self.current_job = None
        self.is_shortcutting = False

    def schedule(self, job):
        if not isinstance(job, object) or not hasattr(job, 'is_finished'):
            raise ValueError('GraphJob cannot be null')
        if job.is_finished():
            raise ValueError('cannot schedule a finished job!')
        self.queue.put(job)
        Thread(target=self.shortcut_and_run_next_job).start()

    def set_final_job(self, job):
        if not isinstance(job, object) or not hasattr(job, 'is_finished'):
            raise ValueError('GraphJob cannot be null')
        if job.is_finished():
            raise ValueError('cannot schedule a finished job!')
        self.final_job = job
        Thread(target=self.maybe_run_next_job).start()

    def is_busy(self):
        return not (self.queue.empty() and self.final_job is None) or self.current_job is not None

    @property
    def current_job_(self):
        return self.current_job

    def finish_all_jobs(self):
        Thread(target=self.shortcut_all).start()

    def dispose(self):
        self.clear_all_jobs()
        self.queue = queue.Queue()
        self.final_job = None

    def clear_all_jobs(self):
        if not hasattr(self, 'current_job'):
            return
        job = self.current_job_
        self.current_job_ = None
        job.dispose()

    def job_finished(self, job):
        print(f'jobFinished() - {job}')
        try:
            while True:
                next_job = self.queue.get_nowait()
                if not hasattr(next_job, 'can_shortcut') or not next_job.can_shortcut():
                    break
                next_job.shortcut()
        except queue.Empty:
            pass

    def shortcut_and_run_next_job(self):
        print('shortcut() - currentJob?:', self.current_job_)
        while True:
            try:
                job = self.queue.get_nowait()
                if not hasattr(job, 'can_shortcut') or not job.can_shortcut():
                    break
                job.shortcut()
            except queue.Empty:
                return

    def shortcut_all(self):
        print('shortcutAll() - currentJob?:', self.current_job_)
        while True:
            try:
                job = self.queue.get_nowait()
                if not hasattr(job, 'can_shortcut') or not job.can_shortcut():
                    break
                job.shortcut()
            except queue.Empty:
                return

    def perform_shortcut_function(self, callback):
        self.is_shortcutting = True
        try:
            callback()
        finally:
            self.is_shortcutting = False

    def shortcut_as_much_as_possible(self, shortcut_all=False):
        if not hasattr(self.current_job_, 'can_shortcut') or not self.current_job_.can_shortcut():
            return False
        while True:
            job = self.queue.get_nowait()
            if not hasattr(job, 'can_shortcut') or not job.can_shortcut() and not shortcut_all:
                break
            job.shortcut()

    def maybe_run_next_job(self):
        print('maybeRunNextJob()')
        if self.is_shortcutting:
            return
        while True:
            try:
                next_job = self.queue.get_nowait()
                if hasattr(next_job, 'can_shortcut') and not next_job.can_shortcut():
                    break
                self.current_job_ = next_job
                next_job.execute(self)
                return
            except queue.Empty:
                pass

    def shortcut_current_job(self):
        print('shortcutCurrentJob()')
        job = self.current_job_
        if hasattr(job, 'can_shortcut') and not job.can_shortcut():
            return False
        job.shortcut()
        self.current_job_ = None
        return True

    def shortcut_pending_jobs(self, shortcut_all=False):
        while True:
            try:
                next_job = self.queue.get_nowait()
                if hasattr(next_job, 'can_shortcut') and not next_job.can_shortcut() and not shortcut_all:
                    break
                next_job.shortcut()
            except queue.Empty:
                return

    def shortcut_final_job(self):
        print('shortcutFinalJob() -', self.final_job)
        if hasattr(self.final_job, 'can_shortcut') and self.final_job.can_shortcut():
            self.final_job.shortcut()
            self.final_job = None
