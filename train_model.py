import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler, LabelEncoder
from scipy.sparse import hstack
import joblib
import socket
import struct

MODEL_FILE = "soc_model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
SCALER_FILE = "scaler.pkl"
LABEL_ENCODER_FILE = "label_encoder.pkl"

def ip_to_int(ip):
    """Convert IPv4 string to integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def train_ml_model(file_path="data/sample_logs.csv",
                   model_file=MODEL_FILE,
                   vectorizer_file=VECTORIZER_FILE,
                   scaler_file=SCALER_FILE,
                   label_encoder_file=LABEL_ENCODER_FILE):
    if not os.path.exists(file_path):
        print(f"⚠️ File not found: {file_path}")
        return

    df = pd.read_csv(file_path)

    # Required columns
    required_columns = ["event_type", "description", "username", "severity", "timestamp", "source_ip"]
    for col in required_columns:
        if col not in df.columns:
            print(f"⚠️ CSV must contain '{col}' column.")
            return

    # Combine text features
    df["text"] = df["event_type"].astype(str) + " " + df["description"].astype(str) + " " + df["username"].astype(str)

    # Vectorize text
    vectorizer = TfidfVectorizer()
    X_text_vec = vectorizer.fit_transform(df["text"])

    # Numeric features: timestamp and source_ip
    df["timestamp_num"] = pd.to_datetime(df["timestamp"], errors="coerce").astype('int64', errors='ignore') // 10**9
    df["timestamp_num"] = df["timestamp_num"].fillna(0)
    df["source_ip_num"] = df["source_ip"].apply(ip_to_int)

    numeric_features = df[["timestamp_num", "source_ip_num"]]
    scaler = StandardScaler()
    X_numeric_scaled = scaler.fit_transform(numeric_features)

    # Combine text and numeric features
    X_combined = hstack([X_text_vec, X_numeric_scaled])

    # Encode labels safely (fill missing, convert to string)
    df["severity"] = df["severity"].fillna("unknown").astype(str)
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["severity"])

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.3, random_state=42
    )

    # Train model with class weights for imbalanced classes
    model = LogisticRegression(max_iter=500, class_weight='balanced')
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("\n📊 Classification Report:\n")
    print(classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    ))

    # Save model, vectorizer, scaler, and label encoder
    joblib.dump(model, model_file)
    joblib.dump(vectorizer, vectorizer_file)
    joblib.dump(scaler, scaler_file)
    joblib.dump(label_encoder, label_encoder_file)

    print(f"\n✅ Model trained and saved: {model_file}")
    print(f"✅ Vectorizer saved: {vectorizer_file}")
    print(f"✅ Scaler saved: {scaler_file}")
    print(f"✅ Label encoder saved: {label_encoder_file}")

if __name__ == "__main__":
    train_ml_model()
