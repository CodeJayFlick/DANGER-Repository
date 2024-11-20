class AbstractBinaryFormatAnalyzer:
    def __init__(self, command):
        self.command = command

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog') -> bool:
        try:
            return self.command.apply_to(program, monitor)
        except Exception as e:
            log.append_exception(e)
            log.status = str(e)

        finally:
            log.copy_from(self.command.get_messages())

    def can_analyze(self, program: 'Program') -> bool:
        return self.command.can_apply(program)

    def get_default_enablement(self, program: 'Program') -> bool:
        return self.command.can_apply(program)
