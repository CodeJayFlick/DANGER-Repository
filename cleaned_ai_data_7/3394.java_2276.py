class AnalysisWorker:
    def analysis_worker_callback(self, program: 'Program', worker_context: object, monitor: 'TaskMonitor') -> bool:
        """Analysis worker callback which performs the desired changes to program while analysis is suspended."""
        raise NotImplementedError

    def get_worker_name(self) -> str:
        """Returns worker name to be used for analysis task monitor. Name should be very short."""
        raise NotImplementedError
