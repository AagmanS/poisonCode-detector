"""Add the actual test benign files to training dataset."""

import pandas as pd
from pcd.scanner import scan_file

# Load existing dataset
df = pd.read_csv('data/processed/dataset.csv')

benign_test_files = [
    'samples/benign/benign_calculator.py',
    'samples/benign/benign_http_client.py',
    'samples/benign/benign_pickle_cache.py'
]

new_rows = []

for file in benign_test_files:
    scan_result = scan_file(file)
    for i, unit in enumerate(scan_result.units):
        new_rows.append({
            'sample_id': f'test_benign_{file.replace("/", "_")}_{i}',
            'code': unit.code,
            'label': 0,  # Benign
            'family': 'none',
            'host_id': file,
            'is_hard_negative': 1,  # These use risky APIs
            'split': 'train'  # Add to training
        })

# Add new rows
new_df = pd.DataFrame(new_rows)
df = pd.concat([df, new_df], ignore_index=True)

# Save
output_path = 'data/processed/dataset.csv'
df.to_csv(output_path, index=False)

print(f"Added {len(new_rows)} samples from test benign files")
print(f"New dataset size: {len(df)}")
print(f"New hard negative count: {(df['is_hard_negative']==1).sum()}")
print("\nNow retrain with:")
print("  pcd train --data data/processed --out models/")
