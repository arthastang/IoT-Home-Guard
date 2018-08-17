"""
Data flow catcher class defination
"""
import os

class DataFlowCatcher(object):
    def __init__(self, current_time):
        self.filename = str(current_time) + '.pcap'

    def run(self):
        os.system("sudo tcpdump -i wlx00117f139169 -G 600 -w "+ self.filename)
