import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))


from inference.predictor import SignatureIDSPredictor
from inference.anomaly_predictor import AnomalyDetector
from inference.fusion_engine import FusionEngine



class FusionIDS:

    def __init__(self):
        self.signature = SignatureIDSPredictor()
        self.anomaly = AnomalyDetector()
        self.fusion = FusionEngine()


    def analyze_flow(self,flow:dict):

        sig_result =self.signature.predict(flow)
        anomaly_result = self.anomaly.detect(flow)

        alert = self.fusion.fuse(sig_result,anomaly_result)

        return alert