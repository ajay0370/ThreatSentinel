import os
import argparse
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support, confusion_matrix

def parse_args():
    parser = argparse.ArgumentParser(description="Train ThreatSentinel Lite ML Engine")
    parser.add_argument(
        "--mode", 
        type=str, 
        choices=["synthetic", "real"], 
        default="synthetic", 
        help="Train using 'synthetic' dataset or 'real' (CIC-IDS2017) dataset"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    os.makedirs("ml_engine/models", exist_ok=True)
    
    csv_path = "ml_engine/synthetic_flows.csv"
    if args.mode == "real":
        csv_path = "ml_engine/real_flows.csv" # Expects user-supplied CIC-IDS2017 or similar dataset
        if not os.path.exists(csv_path):
            print(f"[-] Real dataset '{csv_path}' not found.")
            print("[*] Falling back to synthetic dataset...")
            csv_path = "ml_engine/synthetic_flows.csv"
            
    if not os.path.exists(csv_path):
        print(f"[-] Training dataset '{csv_path}' does not exist.")
        print("[*] Please run data_generator.py first to create it.")
        return

    print(f"[*] Loading training data from '{csv_path}'...")
    df = pd.read_csv(csv_path)
    
    # Define features and label
    feature_cols = [
        'duration', 'pkt_count_out', 'pkt_count_in', 
        'byte_count_out', 'byte_count_in', 'pkt_rate', 
        'byte_rate', 'avg_pkt_sz', 'tcp_flags_syn', 
        'tcp_flags_ack', 'tcp_flags_rst', 'protocol'
    ]
    
    X = df[feature_cols]
    y = df['label']
    
    # Split training and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # 1. Standardize Features
    print("[*] Training Standard Scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 2. Train Isolation Forest (Unsupervised Anomaly Detector)
    # Fit only on normal flows (label = 0) from training set to learn normal behavior
    print("[*] Training Isolation Forest on normal traffic...")
    normal_indices = (y_train == 0)
    X_train_normal = X_train_scaled[normal_indices]
    
    # Train Isolation Forest
    # contamination is the expected proportion of outliers (set to 0.05)
    if_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    if_model.fit(X_train_normal)
    
    # 3. Train Random Forest Classifier (Supervised Multi-Class Classifier)
    print("[*] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train_scaled, y_train)
    
    # 4. Evaluate Supervised Model
    print("[*] Evaluating models...")
    y_pred = rf_model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    conf_matrix = confusion_matrix(y_test, y_pred).tolist()
    
    classes = ['Normal', 'DDoS', 'Port Scan', 'Brute Force']
    class_report = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
    
    # 5. Evaluate Unsupervised Model (Anomaly Detection)
    # Predict anomalies on test set
    # -1 for anomaly, 1 for normal
    if_preds_raw = if_model.predict(X_test_scaled)
    # Map back to: normal = 1 (our label 0), anomaly = -1 (our labels 1, 2, 3)
    if_preds_binary = np.where(if_preds_raw == -1, 1, 0)
    y_test_binary = np.where(y_test > 0, 1, 0)
    
    if_accuracy = accuracy_score(y_test_binary, if_preds_binary)
    if_precision, if_recall, if_f1, _ = precision_recall_fscore_support(y_test_binary, if_preds_binary, average='binary')
    
    # Compile evaluation metrics
    evaluation_metrics = {
        "dataset_mode": args.mode,
        "sample_counts": {
            "total": len(df),
            "train": len(X_train),
            "test": len(X_test)
        },
        "random_forest": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "confusion_matrix": conf_matrix,
            "class_reports": class_report
        },
        "isolation_forest": {
            "accuracy": float(if_accuracy),
            "precision": float(if_precision),
            "recall": float(if_recall),
            "f1_score": float(if_f1)
        }
    }
    
    # Save Models
    joblib.dump(scaler, "ml_engine/models/scaler.pkl")
    joblib.dump(if_model, "ml_engine/models/isolation_forest.pkl")
    joblib.dump(rf_model, "ml_engine/models/random_forest.pkl")
    print("[+] Models saved to 'ml_engine/models/'")
    
    # Save evaluation report
    metrics_path = "ml_engine/models/evaluation.json"
    with open(metrics_path, 'w') as f:
        json.dump(evaluation_metrics, f, indent=4)
    print(f"[+] Saved evaluation metrics to {metrics_path}")
    
    print("\n=== Random Forest Performance Summary ===")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("\n=== Isolation Forest Anomaly Detection Summary ===")
    print(f"Accuracy:  {if_accuracy:.4f}")
    print(f"F1-Score:  {if_f1:.4f}")

if __name__ == "__main__":
    main()
