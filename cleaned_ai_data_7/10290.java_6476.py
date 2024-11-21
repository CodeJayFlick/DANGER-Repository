import logging

class Log4jErrorLogger:
    def __init__(self):
        self.logger = None

    @staticmethod
    def get_logger(originator):
        if originator is None:
            return logging.getLogger("(null)")
        elif isinstance(originator, str):
            return logging.getLogger(originator)
        else:
            return logging.getLogger(originator.__class__.__name__)

    def debug(self, originator, message):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.debug((Message(**message)))
        else:
            logger.debug(message)

    def debug(self, originator, message, throwable):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.debug((Message(**message)), throwable)
        else:
            logger.debug(message, throwable)

    def error(self, originator, message):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.error((Message(**message)))
        else:
            logger.error(message)

    def error(self, originator, message, throwable):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.error((Message(**message)), throwable)
        else:
            logger.error(message, throwable)

    def info(self, originator, message):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.info((Message(**message)))
        else:
            logger.info(message)

    def info(self, originator, message, throwable):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.info((Message(**message)), throwable)
        else:
            logger.info(message, throwable)

    def trace(self, originator, message):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.trace((Message(**message)))
        else:
            logger.trace(message)

    def trace(self, originator, message, throwable):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.trace((Message(**message)), throwable)
        else:
            logger.trace(message, throwable)

    def warn(self, originator, message):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.warn((Message(**message)))
        else:
            logger.warn(message)

    def warn(self, originator, message, throwable):
        logger = self.get_logger(originator)
        if isinstance(message, dict) and 'message' in message:
            logger.warn((Message(**message)), throwable)
        else:
            logger.warn(message, throwable)


class Message(dict):
    pass
