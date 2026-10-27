"""Check dataset quality."""
import pandas as pd

df = pd.read_csv('data/processed/dataset.csv')
print('Dataset stats:')
print(df.groupby(['split', 'label']).size())
print(f'\nTotal samples: {len(df)}')
print(f'Hard negatives: {(df["is_hard_negative"] == 1).sum()}')
print(f'Hard negative %: {(df["is_hard_negative"] == 1).sum() / len(df) * 100:.1f}%')

# Check benign samples
benign = df[df['label'] == 0]
print(f'\nBenign samples: {len(benign)}')
print('Sample benign code lengths:')
for i, row in benign.head(5).iterrows():
    print(f"  {len(row['code'])} chars")
