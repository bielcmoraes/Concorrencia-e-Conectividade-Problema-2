# lamport_clock.py

class LamportClock:
    def __init__(self):
        self.time = 0

    def increment(self):
        self.time += 1

    def get_time(self):
        return self.time

    def update(self, new_time):
        self.time = max(self.time, new_time) + 1
