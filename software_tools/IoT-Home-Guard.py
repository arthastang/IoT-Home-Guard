from .data_flow_catcher import DataFlowCatcher
from .traffic_analysis_engine import TrafficAnalysisEngine
import time



if __name__ == "__main__":
    current_time = time.time()
    catcher = new DataFlowCatcher(current_time)
    catcher.run()

    device_name = raw_input("Input a device name:")

    engine = new TrafficAnalysisEngine(current_time, device_name)
    engine.run()
    
