import logging
from collections import defaultdict

class SkriptLogger:
    SEVERE = logging.severe
    DEBUG = logging.info  # CraftBukkit 1.7+ uses the worst logging library I've ever encountered

    verbosity = 'NORMAL'
    debug = False

    LOGGER = None

    def __init__(self):
        self.handlers = defaultdict(list)

    @staticmethod
    def start_retaining_log():
        return RetainingLogHandler().start()

    @staticmethod
    def start_parse_log_handler():
        return ParseLogHandler().start()

    @staticmethod
    def start_log_handler(h):
        SkriptLogger.LOGGER.addHandler(h)
        return h

    @staticmethod
    def remove_handler(h):
        if not SkriptLogger.handlers.contains(h):
            return
        if len(SkriptLogger.handlers[h]) > 0:
            logging.severe("[Skript] " + str(len(SkriptLogger.handlers[h])) + " log handler" +
                           (1 if len(SkriptLogger.handlers[h]) == 1 else 's were') +
                           " not stopped properly!" +
                           " (at " + get_caller() + ") [" +
                           "if you're a server admin and you see this message please file a bug report at https://github.com/SkriptLang/skript/issues if there is not already one]")

    @staticmethod
    def is_stopped(h):
        return h not in SkriptLogger.handlers

    @staticmethod
    def get_caller():
        for e in logging.currentframe().f_back.f_code.co_names:
            if not e.startswith(Skript.__package__.name):
                return e
        return None

    @classmethod
    def set_verbosity(cls, v):
        SkriptLogger.verbosity = v
        SkriptLogger.debug = v >= 'DEBUG'

    @staticmethod
    def debug():
        return SkriptLogger.debug

    @classmethod
    def set_node(cls, node=None):
        ParserInstance.set_node(node)

    @classmethod
    def get_node(cls):
        return ParserInstance.get().get_node()

    @classmethod
    def log(cls, level=logging.INFO, message=''):
        if cls.log_normal():
            logging.log(level, "[Skript] " + message)
        else:
            for h in SkriptLogger.handlers.values():
                r = h.log(message)
                if r == 'CACHED':
                    return
                elif r == 'DO_NOT_LOG':
                    entry.discarded("denied by " + str(h))
                    return
                elif r == 'LOG':
                    continue

    @classmethod
    def log_all(cls, entries):
        for e in entries:
            cls.log(e.level, e.message)

    @classmethod
    def log_tracked(cls, level=logging.INFO, message='', quality=''):
        if Skript.verbosity >= 'DEBUG' and not Skript.testing():
            logging.log(level, "[Skript] " + message)
