"""
Data flow catcher class defination
"""
import pyshark


class DataFlowCatcher(object):
    def __init__(self, current_time):
        self.filename = current_time
        return

    def run(self):
        #call pyshark api save as self.filename
        return 
