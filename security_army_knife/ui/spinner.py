import sys
import time
import itertools
import threading


class Spinner:
    def __init__(self):
        self.default_spinner_cycle = itertools.cycle(
            ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        )
        self.http_request_spinner_cycle = itertools.cycle(["◐", "◓", "◑", "◒"])
        self.spinner_cycle = self.default_spinner_cycle
        self.stop_running = threading.Event()
        self.thread = threading.Thread(target=self._spin)

    def _spin(self):
        while not self.stop_running.is_set():
            sys.stdout.write(next(self.spinner_cycle))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write("\b")
        sys.stdout.write("\b")

    def start(self):
        self.stop_running.clear()
        if not self.thread.is_alive():
            self.thread = threading.Thread(target=self._spin)
            self.thread.start()

    def stop(self):
        self.stop_running.set()
        self.thread.join()
        sys.stdout.write("\b")
        sys.stdout.flush()

    def set_default_spinner(self):
        self.spinner_cycle = self.default_spinner_cycle

    def set_http_request_spinner(self):
        self.spinner_cycle = self.http_request_spinner_cycle
