"""Debug why benign files get high scores."""

from pcd.model import PCDModel
from pcd.scanner import scan_file
from pcd.features import extract_features

model = PCDModel.load('models/pcd_model.joblib')

benign_files = [
    'samples/benign/benign_calculator.py',
    'samples/benign/benign_http_client.py',
    'samples/benign/benign_pickle_cache.py'
]

print("Debugging benign file predictions...")
print("=" * 70)
print(f"Model thresholds: suspicious={model.suspicious_threshold:.2f}, malicious={model.malicious_threshold:.2f}")
print()

for file in benign_files:
    print(f"\n{file}:")
    print("-" * 70)
    
    scan_result = scan_file(file)
    
    for unit in scan_result.units:
        score, verdict = model.predict(unit.code)
        print(f"  Unit '{unit.name}': ML score={score:.3f}, verdict={verdict}")
        
        # Extract features to see what's high
        features = extract_features(unit.code)
        
        # Find suspicious features
        suspicious_features = {k: v for k, v in features.items() if v > 0 and 'count' in k and v > 0}
        if suspicious_features:
            print(f"    Non-zero dangerous features:")
            for feat, val in sorted(suspicious_features.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"      {feat}: {val}")
        
        # Check dataflow
        if features.get('exfil_pair', 0) > 0:
            print(f"    ⚠ exfil_pair triggered")
        if features.get('decode_exec_pair', 0) > 0:
            print(f"    ⚠ decode_exec_pair triggered")
