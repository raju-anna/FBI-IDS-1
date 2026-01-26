class FusionEngine:

    def __init__(self,
                 sig_threshold=0.40,
                 anomaly_score_threshold=-0.15):
        self.sig_threshold = sig_threshold
        self.anomaly_score_threshold = anomaly_score_threshold

    def fuse(self, sig_result, anomaly_result):

        if sig_result and sig_result['label_id'] != 0 and sig_result["confidence"] >= self.sig_threshold:
            if anomaly_result["is_anomalous"]:
                sig_result["severity"] = "Critical"
                sig_result["fusion"] = "Signature+Anomaly"
            else:
                sig_result["fusion"] = "SignatureOnly"
            return sig_result

        if (anomaly_result["is_anomalous"] and
            anomaly_result["anomaly_score"] <= self.anomaly_score_threshold):
            return {
                "label_name": "Unknown-Anomaly",
                "family": "Anomalous Behavior",
                "severity": "High",
                "fusion": "AnomalyOnly",
                "anomaly_score": anomaly_result["anomaly_score"]
            }

        return None
