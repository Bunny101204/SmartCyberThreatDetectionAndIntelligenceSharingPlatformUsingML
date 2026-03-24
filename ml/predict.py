import joblib
import numpy as np
from collections import Counter

# Load models and preprocessors
rf_model = joblib.load('rf_model.pkl')
xgb_model = joblib.load('xgb_model.pkl')
svm_model = joblib.load('svm_model.pkl')
dt_model = joblib.load('dt_model.pkl')

scaler = joblib.load('scaler.pkl')
le_protocol = joblib.load('le_protocol.pkl')
le_service = joblib.load('le_service.pkl')
le_flag = joblib.load('le_flag.pkl')
le_y = joblib.load('le_y.pkl')

# Feature order
features = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

def preprocess_input(data):
    # Encode categorical
    data['protocol_type'] = le_protocol.transform([data['protocol_type']])[0]
    data['service'] = le_service.transform([data['service']])[0]
    data['flag'] = le_flag.transform([data['flag']])[0]

    # Get feature vector
    X = np.array([data[feat] for feat in features]).reshape(1, -1)
    X_scaled = scaler.transform(X)
    return X_scaled

def predict_ensemble(X):
    preds = []
    preds.append(rf_model.predict(X)[0])
    preds.append(xgb_model.predict(X)[0])
    preds.append(svm_model.predict(X)[0])
    preds.append(dt_model.predict(X)[0])

    # Majority vote
    vote = Counter(preds).most_common(1)[0][0]
    return le_y.inverse_transform([vote])[0]

def predict_threat(data):
    X = preprocess_input(data)
    prediction = predict_ensemble(X)
    is_attack = prediction != 'normal'
    attack_type = prediction if is_attack else None
    return {
        "src_ip": data.get("src_ip", "unknown"),
        "dst_ip": data.get("dst_ip", "unknown"),
        "prediction": "Attack" if is_attack else "Normal",
        "attack_type": attack_type
    }