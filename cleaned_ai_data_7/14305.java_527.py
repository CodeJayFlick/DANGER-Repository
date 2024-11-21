import logging

class ErrorView:
    def display(self):
        logging.error('Error 500')

if __name__ == '__main__':
    error_view = ErrorView()
    error_view.display()

