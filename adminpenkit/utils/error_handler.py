class ErrorHandler:
    def __init__(self, logger):
        self.logger = logger
        
    def handle_error(self, error, context=""):
        error_msg = f"{context}: {str(error)}"
        self.logger.error(error_msg)
        return error_msg
