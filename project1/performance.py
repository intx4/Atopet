import csv
"""Used for logging purposes for performance analysis"""
class Analyst:
    def __init__(self):
        self.bytes_in = 0
        self.bytes_out = 0

    def __increment_in__(self, amount: int):
        self.bytes_in += amount

    def __increment_out__(self, amount: int):
        self.bytes_out += amount

    def __set_num__(self, num: int):
        self.num = num
        self.requests = 0
    def __log__(self):
        self.requests += 1
        if self.requests == self.num**2:
            print(f"[ BYTES IN ] = {self.bytes_in}")
            print(f"[ BYTES OUT ] = {self.bytes_out}")
            with open('bytes_addition.csv', 'a') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([self.num, self.bytes_in, self.bytes_out])
