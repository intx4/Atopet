import csv
import time
import os

"""Used for logging purposes for performance analysis"""
class PerformanceDecorator:
    file = os.getcwd() + '/performance_analysis'
    timer = None
    def __init__(self, directory, config_name):
        self.bytes_in = 0
        self.bytes_out = 0
        self.config_name = config_name
        self.file = self.file + directory

    def increment_byte_in(self, amount: int):
        self.bytes_in += amount

    def increment_byte_out(self, amount: int):
        self.bytes_out += amount

    def log(self, file, data):
        with open(file, 'a+') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(data)

    def start_timer(self):
        self.timer = time.time()

    def stop_timer(self):
        diff = [self.config_name, time.time()-self.timer]
        file = self.file + 'runtime.csv'
        self.log(file, diff)
        file = self.file + 'dataflow.csv'
        data = [self.config_name, self.bytes_in, self.bytes_out]
        self.log(file, data)
