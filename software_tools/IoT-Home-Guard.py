from data_flow_catcher.data_flow_catcher import DataFlowCatcher
from traffic_analysis_engine.traffic_analysis_engine import TrafficAnalysisEngine
import time

if __name__ == "__main__":
    current_time = time.time()
    catcher = DataFlowCatcher(current_time)
    catcher.run()

    # device_name = raw_input("Input a device name:")

    # engine = TrafficAnalysisEngine(current_time, device_name)
    # engine.run()

    engine = TrafficAnalysisEngine(str(current_time), "xiaoaitongxue")
    engine.run()
    
