import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
import joblib
import os

# Download NSL-KDD dataset if not exists
def download_dataset():
    if not os.path.exists('../data/KDDTrain+.txt'):
        os.system('wget -O ../data/KDDTrain+.txt https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt')
    if not os.path.exists('../data/KDDTest+.txt'):
        os.system('wget -O ../data/KDDTest+.txt https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt')

# Load dataset
def load_data():
    download_dataset()
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
               'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
               'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
               'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
               'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
               'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty']
    df = pd.read_csv('../data/KDDTrain+.txt', header=None, names=columns)
    df['label'] = df['label'].astype(str).str.rstrip('.')
    df['label'] = df['label'].apply(lambda x: 'attack' if x != 'normal' else 'normal')
    return df

# Preprocessing
def preprocess_data(df):
    # Identify categorical columns
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        joblib.dump(le, f'le_{col}.pkl')

    # Features and labels
    X = df.drop(['label', 'difficulty'], axis=1)
    y = df['label']

    # Encode y
    le_y = LabelEncoder()
    y_encoded = le_y.fit_transform(y)
    joblib.dump(le_y, 'le_y.pkl')

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, 'scaler.pkl')

    return X_scaled, y_encoded

# Train models
def train_models(X, y):
    models = {
        'rf': RandomForestClassifier(n_estimators=100, random_state=42),
        'xgb': XGBClassifier(random_state=42),
        'svm': SVC(probability=True, random_state=42),
        'dt': DecisionTreeClassifier(random_state=42)
    }

    trained_models = {}
    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X, y)
        trained_models[name] = model
        joblib.dump(model, f'{name}_model.pkl')

    return trained_models

if __name__ == "__main__":
    df = load_data()
    X, y = preprocess_data(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    models = train_models(X_train, y_train)
    print("Models trained and saved.")