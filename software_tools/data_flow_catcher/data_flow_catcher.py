"""
Data flow catcher class defination
"""
import os

def getNICNames():
    print("Choose the Network Interface Controller you will use:")
    
    dirNumber = 1
    dirList = os.listdir("/sys/class/net")
    for eachDir in dirList:
        print(str(dirNumber) + ". " + eachDir)
        dirNumber += 1 

    dirChoice = int(input("Input the number:"))

    return dirList[dirChoice - 1]


class DataFlowCatcher(object):
    def __init__(self, current_time):
        self.filename = 'pcaps/' + current_time + '.pcap'

    def run(self):
        NICName = getNICNames()
        print("Start Data Flow Catcher...\nIt will run in 1 minute...")
        os.system("sudo tcpdump -i " + NICName + " -G 60 -W 1 -w "+ self.filename)
