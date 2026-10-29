import os
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from django.conf import settings

# Features list used for kernel behavioral analysis
FEATURE_NAMES = [
    'syscall_freq',         # System calls per second
    'cpu_usage',            # CPU usage percentage
    'mem_usage_mb',         # Memory consumption in MB
    'thread_count',         # Number of active threads
    'open_fds',             # Open file handles/descriptors
    'file_op_rate',         # File access/write rate
    'net_conn_rate',        # Network connection attempts
    'is_priv_escalation',   # 1 if privileged/setuid/admin change detected, else 0
    'suspicious_path',      # 1 if spawned from /tmp, /dev/shm, Temp directories
    'sensitive_target',     # 1 if targeting /etc/shadow, SAM, hosts, system keys
]

BASELINE_STATS = {
    'syscall_freq': {'mean': 18.5, 'std': 12.0},
    'cpu_usage': {'mean': 4.2, 'std': 6.5},
    'mem_usage_mb': {'mean': 45.0, 'std': 35.0},
    'thread_count': {'mean': 3.5, 'std': 2.5},
    'open_fds': {'mean': 8.0, 'std': 6.0},
    'file_op_rate': {'mean': 2.1, 'std': 3.0},
    'net_conn_rate': {'mean': 0.8, 'std': 1.2},
    'is_priv_escalation': {'mean': 0.01, 'std': 0.05},
    'suspicious_path': {'mean': 0.01, 'std': 0.05},
    'sensitive_target': {'mean': 0.005, 'std': 0.03},
}

class KernelAnomalyDetector:
    def __init__(self):
        self.model_dir = getattr(settings, 'ML_MODELS_DIR', Path(__file__).resolve().parent / 'saved_models')
        os.makedirs(self.model_dir, exist_ok=True)
        self.model_path = os.path.join(self.model_dir, 'isolation_forest.joblib')
        self.scaler_path = os.path.join(self.model_dir, 'scaler.joblib')
        self.model = None
        self.scaler = None
        self.load_or_train()

    def generate_baseline_data(self, n_samples=2500):
        """Generates realistic normal OS kernel baseline training data using pure NumPy."""
        np.random.seed(42)
        syscall_freq = np.clip(np.random.normal(18.0, 8.0, n_samples), 1.0, 80.0)
        cpu_usage = np.clip(np.random.exponential(3.5, n_samples), 0.1, 35.0)
        mem_usage_mb = np.clip(np.random.normal(45.0, 20.0, n_samples), 5.0, 150.0)
        thread_count = np.clip(np.random.poisson(3.0, n_samples), 1, 15)
        open_fds = np.clip(np.random.poisson(8.0, n_samples), 1, 35)
        file_op_rate = np.clip(np.random.exponential(2.0, n_samples), 0.0, 15.0)
        net_conn_rate = np.clip(np.random.exponential(0.6, n_samples), 0.0, 5.0)
        is_priv_escalation = np.zeros(n_samples)
        suspicious_path = np.zeros(n_samples)
        sensitive_target = np.zeros(n_samples)

        # Add 1.5% natural background noise / mild edge cases
        noise_idx = np.random.choice(n_samples, int(n_samples * 0.015), replace=False)
        for i in noise_idx:
            syscall_freq[i] *= 1.8
            cpu_usage[i] *= 1.5
            open_fds[i] += 10

        matrix = np.column_stack([
            syscall_freq, cpu_usage, mem_usage_mb, thread_count, open_fds,
            file_op_rate, net_conn_rate, is_priv_escalation, suspicious_path, sensitive_target
        ])
        return matrix

    def train(self, X_train=None, contamination=0.04, n_estimators=120):
        """Trains Isolation Forest model on kernel behavioral features."""
        if X_train is None:
            X_train = self.generate_baseline_data(n_samples=3000)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(X_train)

        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        model.fit(scaled_features)

        self.model = model
        self.scaler = scaler

        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

        return {
            'samples': len(X_train),
            'contamination': contamination,
            'n_estimators': n_estimators,
            'status': 'Model trained and saved successfully.'
        }

    def load_or_train(self):
        """Loads saved models or trains a fresh baseline."""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
            else:
                self.train()
        except Exception:
            self.train()

    def extract_features(self, event_dict):
        """
        Converts raw kernel event dictionary into structured numerical features.
        """
        raw = event_dict.get('raw_data', {})

        # System call rate
        syscall_freq = float(raw.get('syscall_freq', raw.get('syscalls_per_sec', 15.0)))
        cpu_usage = float(raw.get('cpu_usage', raw.get('cpu_percent', 2.0)))
        mem_usage_mb = float(raw.get('mem_usage_mb', raw.get('memory_mb', 30.0)))
        thread_count = float(raw.get('thread_count', 2.0))
        open_fds = float(raw.get('open_fds', raw.get('num_fds', 5.0)))
        file_op_rate = float(raw.get('file_op_rate', 1.0))
        net_conn_rate = float(raw.get('net_conn_rate', 0.0))

        # Privilege escalation
        is_priv_escalation = 1.0 if (
            event_dict.get('is_privileged', False) or
            event_dict.get('event_type') == 'privilege' or
            'setuid' in event_dict.get('syscall_name', '').lower() or
            'capset' in event_dict.get('syscall_name', '').lower() or
            raw.get('privilege_escalation', False)
        ) else 0.0

        # Suspicious path
        path = str(event_dict.get('binary_path', '')).lower()
        suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp', '\\temp\\', 'appdata\\local\\temp']
        suspicious_path = 1.0 if any(sp in path for sp in suspicious_paths) or raw.get('suspicious_path', False) else 0.0

        # Sensitive target
        target = str(event_dict.get('target_path', '')).lower()
        sensitive_targets = [
            '/etc/shadow', '/etc/passwd', '/etc/sudoers',
            'system32\\config\\sam', 'system32\\config\\system',
            '.ssh/id_rsa', 'authorized_keys', 'ntds.dit'
        ]
        sensitive_target = 1.0 if any(st in target for st in sensitive_targets) or raw.get('sensitive_target', False) else 0.0

        vector = {
            'syscall_freq': syscall_freq,
            'cpu_usage': cpu_usage,
            'mem_usage_mb': mem_usage_mb,
            'thread_count': thread_count,
            'open_fds': open_fds,
            'file_op_rate': file_op_rate,
            'net_conn_rate': net_conn_rate,
            'is_priv_escalation': is_priv_escalation,
            'suspicious_path': suspicious_path,
            'sensitive_target': sensitive_target,
        }
        return vector

    def predict(self, event_dict):
        """
        Evaluates a kernel event and returns anomaly score, threat level, and explanation.
        """
        if self.model is None or self.scaler is None:
            self.load_or_train()

        features = self.extract_features(event_dict)
        feature_row = np.array([[features[name] for name in FEATURE_NAMES]])
        scaled = self.scaler.transform(feature_row)

        # Decision function: in Isolation Forest, positive is normal, negative is anomalous
        raw_score = self.model.decision_function(scaled)[0]

        # Calibrate into [0.0, 1.0] anomaly score where 1.0 is extremely anomalous
        k = 12.0
        x0 = 0.02
        anomaly_score = 1.0 / (1.0 + np.exp(k * (raw_score - x0)))

        # Heuristic boosts for explicit high-severity kernel security indicators
        if features['is_priv_escalation'] > 0:
            anomaly_score = max(anomaly_score, 0.88)
        if features['sensitive_target'] > 0:
            anomaly_score = max(anomaly_score, 0.92)
        if features['suspicious_path'] > 0 and features['cpu_usage'] > 50:
            anomaly_score = max(anomaly_score, 0.89)
        if features['syscall_freq'] > 400:
            anomaly_score = max(anomaly_score, 0.94)

        anomaly_score = round(float(np.clip(anomaly_score, 0.02, 0.99)), 4)

        # Threat classification
        if anomaly_score < 0.45:
            threat_level = 'NORMAL'
            is_anomaly = False
        elif anomaly_score < 0.60:
            threat_level = 'LOW'
            is_anomaly = True
        elif anomaly_score < 0.75:
            threat_level = 'MEDIUM'
            is_anomaly = True
        elif anomaly_score < 0.90:
            threat_level = 'HIGH'
            is_anomaly = True
        else:
            threat_level = 'CRITICAL'
            is_anomaly = True

        # Generate feature deviation explanations
        explanation = {}
        for fname in FEATURE_NAMES:
            val = features[fname]
            base_mean = BASELINE_STATS[fname]['mean']
            base_std = BASELINE_STATS[fname]['std']
            z_score = (val - base_mean) / (base_std if base_std > 0 else 1.0)
            if z_score > 2.0 or (fname in ['is_priv_escalation', 'suspicious_path', 'sensitive_target'] and val > 0):
                explanation[fname] = {
                    'value': val,
                    'baseline_mean': base_mean,
                    'z_score': round(float(z_score), 2),
                    'severity': 'Critical' if z_score > 4.0 or val == 1.0 else 'High'
                }

        return {
            'anomaly_score': anomaly_score,
            'is_anomaly': is_anomaly,
            'threat_level': threat_level,
            'feature_vector': features,
            'explanation': explanation,
            'raw_decision_score': float(raw_score)
        }

# Global singleton
detector = KernelAnomalyDetector()
