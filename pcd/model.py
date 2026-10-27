"""Model training, evaluation, and inference."""

import json
import joblib
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, Optional, List

import pandas as pd
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve
)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from pcd.parsing import normalize_code_for_tokens
from pcd.features import extract_features


class PCDModel:
    """PoisonCode Detector ML model ensemble."""
    
    def __init__(self, benign_threshold: float = 0.20,
                 suspicious_threshold: float = 0.40, 
                 malicious_threshold: float = 0.70):
        self.feature_model = None  # HistGradientBoostingClassifier
        self.token_model = None    # LogisticRegression
        self.vectorizer = None     # TfidfVectorizer
        self.feature_names = None
        self.benign_threshold = benign_threshold
        self.suspicious_threshold = suspicious_threshold
        self.malicious_threshold = malicious_threshold
        self.ensemble_weights = (0.6, 0.4)  # (feature_model, token_model)
    
    def train(self, dataset_path: str, seed: int = 42) -> Dict:
        """
        Train the ensemble model.
        
        Args:
            dataset_path: Path to dataset.csv
            seed: Random seed
            
        Returns:
            Training metrics dict
        """
        # Load dataset
        df = pd.read_csv(dataset_path)
        
        # Split by train/val/test
        train_df = df[df['split'] == 'train']
        val_df = df[df['split'] == 'validation']
        
        # Extract features for all samples
        print("Extracting features...")
        X_train_feat = []
        X_val_feat = []
        
        for code in train_df['code']:
            feats = extract_features(code)
            X_train_feat.append(feats)
        
        for code in val_df['code']:
            feats = extract_features(code)
            X_val_feat.append(feats)
        
        # Convert to DataFrame
        X_train_feat_df = pd.DataFrame(X_train_feat)
        X_val_feat_df = pd.DataFrame(X_val_feat)
        
        # Ensure same columns
        all_cols = list(X_train_feat_df.columns)
        self.feature_names = all_cols
        
        y_train = train_df['label'].values
        y_val = val_df['label'].values
        
        # Train feature model
        print("Training feature model...")
        self.feature_model = HistGradientBoostingClassifier(
            max_iter=100,
            random_state=seed,
            early_stopping=True,
            validation_fraction=0.1
        )
        self.feature_model.fit(X_train_feat_df, y_train)
        
        # Train token model
        print("Training token model...")
        train_codes_normalized = [normalize_code_for_tokens(code) 
                                  for code in train_df['code']]
        val_codes_normalized = [normalize_code_for_tokens(code) 
                               for code in val_df['code']]
        
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=50000,
            sublinear_tf=True,
            token_pattern=r'\S+'
        )
        X_train_tokens = self.vectorizer.fit_transform(train_codes_normalized)
        X_val_tokens = self.vectorizer.transform(val_codes_normalized)
        
        self.token_model = LogisticRegression(
            class_weight='balanced',
            max_iter=200,
            random_state=seed
        )
        self.token_model.fit(X_train_tokens, y_train)
        
        # Get predictions for calibration
        pred_feat_train = self.feature_model.predict_proba(X_train_feat_df)[:, 1]
        pred_tok_train = self.token_model.predict_proba(X_train_tokens)[:, 1]
        pred_ensemble_train = (self.ensemble_weights[0] * pred_feat_train + 
                              self.ensemble_weights[1] * pred_tok_train)
        
        pred_feat_val = self.feature_model.predict_proba(X_val_feat_df)[:, 1]
        pred_tok_val = self.token_model.predict_proba(X_val_tokens)[:, 1]
        pred_ensemble_val = (self.ensemble_weights[0] * pred_feat_val + 
                            self.ensemble_weights[1] * pred_tok_val)
        
        # Tune thresholds on validation set
        # Suspicious threshold: aim for >=95% recall
        recalls = []
        thresholds = np.arange(0.1, 0.6, 0.05)
        for thresh in thresholds:
            preds = (pred_ensemble_val >= thresh).astype(int)
            rec = recall_score(y_val, preds)
            recalls.append(rec)
        
        # Find threshold with recall >= 0.95
        for i, rec in enumerate(recalls):
            if rec >= 0.95:
                self.suspicious_threshold = thresholds[i]
                break
        
        # Malicious threshold: aim for >=95% precision
        precisions = []
        thresholds = np.arange(0.5, 0.9, 0.05)
        for thresh in thresholds:
            preds = (pred_ensemble_val >= thresh).astype(int)
            if preds.sum() > 0:
                prec = precision_score(y_val, preds)
                precisions.append(prec)
            else:
                precisions.append(0.0)
        
        for i, prec in enumerate(precisions):
            if prec >= 0.95:
                self.malicious_threshold = thresholds[i]
                break
        
        print(f"Tuned thresholds: suspicious={self.suspicious_threshold:.2f}, "
              f"malicious={self.malicious_threshold:.2f}")
        
        # Return metrics
        preds_val = (pred_ensemble_val >= self.malicious_threshold).astype(int)
        metrics = {
            'precision': precision_score(y_val, preds_val),
            'recall': recall_score(y_val, preds_val),
            'f1': f1_score(y_val, preds_val),
            'roc_auc': roc_auc_score(y_val, pred_ensemble_val),
            'benign_threshold': self.benign_threshold,
            'suspicious_threshold': self.suspicious_threshold,
            'malicious_threshold': self.malicious_threshold
        }
        
        return metrics
    
    def predict(self, code: str) -> Tuple[float, str]:
        """
        Predict score for a code sample.
        
        Args:
            code: Python source code
            
        Returns:
            Tuple of (score, verdict)
        """
        # Extract features
        feats = extract_features(code)
        feat_df = pd.DataFrame([feats])
        
        # Ensure all feature columns exist
        for col in self.feature_names:
            if col not in feat_df.columns:
                feat_df[col] = 0
        feat_df = feat_df[self.feature_names]
        
        # Predict with feature model
        pred_feat = self.feature_model.predict_proba(feat_df)[0, 1]
        
        # Predict with token model
        code_normalized = normalize_code_for_tokens(code)
        tokens = self.vectorizer.transform([code_normalized])
        pred_tok = self.token_model.predict_proba(tokens)[0, 1]
        
        # Ensemble
        score = (self.ensemble_weights[0] * pred_feat + 
                self.ensemble_weights[1] * pred_tok)
        
        # Determine verdict
        if score < 0.20:
            verdict = "BENIGN"
        elif score >= self.malicious_threshold:
            verdict = "MALICIOUS"
        elif score >= self.suspicious_threshold:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"  # Between benign and suspicious (shouldn't happen with 0.2/0.1)
        
        return float(score), verdict
    
    def save(self, model_path: str, dataset_path: str):
        """Save model and metadata."""
        model_data = {
            'feature_model': self.feature_model,
            'token_model': self.token_model,
            'vectorizer': self.vectorizer,
            'feature_names': self.feature_names,
            'benign_threshold': self.benign_threshold,
            'suspicious_threshold': self.suspicious_threshold,
            'malicious_threshold': self.malicious_threshold,
            'ensemble_weights': self.ensemble_weights
        }
        joblib.dump(model_data, model_path)
        
        # Save model card
        with open(dataset_path, 'rb') as f:
            dataset_hash = hashlib.md5(f.read()).hexdigest()
        
        model_card = {
            'version': '0.1.0',
            'training_date': datetime.now().isoformat(),
            'dataset_hash': dataset_hash,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'benign_threshold': self.benign_threshold,
            'suspicious_threshold': self.suspicious_threshold,
            'malicious_threshold': self.malicious_threshold,
            'ensemble_weights': self.ensemble_weights
        }
        
        card_path = str(Path(model_path).parent / 'model_card.json')
        with open(card_path, 'w') as f:
            json.dump(model_card, f, indent=2)
    
    @classmethod
    def load(cls, model_path: str) -> 'PCDModel':
        """Load model from file."""
        model_data = joblib.load(model_path)
        
        model = cls(
            benign_threshold=model_data.get('benign_threshold', 0.20),
            suspicious_threshold=model_data['suspicious_threshold'],
            malicious_threshold=model_data['malicious_threshold']
        )
        model.feature_model = model_data['feature_model']
        model.token_model = model_data['token_model']
        model.vectorizer = model_data['vectorizer']
        model.feature_names = model_data['feature_names']
        model.ensemble_weights = model_data['ensemble_weights']
        
        return model


def evaluate_model(model: PCDModel, dataset_path: str, output_dir: str) -> Dict:
    """
    Evaluate model and generate metrics and plots.
    
    Args:
        model: Trained model
        dataset_path: Path to dataset
        output_dir: Directory for outputs
        
    Returns:
        Metrics dictionary
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load test data
    df = pd.read_csv(dataset_path)
    test_df = df[df['split'] == 'test']
    
    # Get predictions
    print("Evaluating on test set...")
    scores = []
    for code in test_df['code']:
        score, _ = model.predict(code)
        scores.append(score)
    
    scores = np.array(scores)
    y_test = test_df['label'].values
    
    # Binary predictions at malicious threshold
    preds = (scores >= model.malicious_threshold).astype(int)
    
    # Metrics
    precision = precision_score(y_test, preds)
    recall = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    roc_auc = roc_auc_score(y_test, scores)
    
    # False positive rate on benign
    benign_mask = y_test == 0
    fpr_benign = (preds[benign_mask] == 1).sum() / benign_mask.sum()
    
    # False positive rate on hard negatives
    hard_neg_mask = (test_df['is_hard_negative'] == 1).values & benign_mask
    if hard_neg_mask.sum() > 0:
        fpr_hard_neg = (preds[hard_neg_mask] == 1).sum() / hard_neg_mask.sum()
    else:
        fpr_hard_neg = 0.0
    
    # Per-family recall
    family_recalls = {}
    for family in ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10']:
        family_mask = test_df['family'] == family
        if family_mask.sum() > 0:
            family_recall = recall_score(y_test[family_mask], preds[family_mask])
            family_recalls[family] = family_recall
    
    metrics = {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'fpr_all_benign': fpr_benign,
        'fpr_hard_negatives': fpr_hard_neg,
        'per_family_recall': family_recalls
    }
    
    # Save metrics
    with open(output_path / 'metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, preds)
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    plt.colorbar()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ['Benign', 'Malicious'])
    plt.yticks(tick_marks, ['Benign', 'Malicious'])
    
    # Add values to cells
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(cm[i, j]), ha='center', va='center')
    
    plt.tight_layout()
    plt.savefig(output_path / 'confusion_matrix.png', dpi=100)
    plt.close()
    
    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, scores)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f'ROC (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], 'k--', label='Random')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path / 'roc_curve.png', dpi=100)
    plt.close()
    
    print(f"\nTest Set Metrics:")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall: {recall:.3f}")
    print(f"  F1: {f1:.3f}")
    print(f"  ROC-AUC: {roc_auc:.3f}")
    print(f"  FPR (all benign): {fpr_benign:.3f}")
    print(f"  FPR (hard negatives): {fpr_hard_neg:.3f}")
    
    return metrics


def leave_one_family_out_eval(dataset_path: str, output_dir: str, seed: int = 42) -> Dict:
    """
    Leave-one-family-out evaluation.
    
    Args:
        dataset_path: Path to dataset
        output_dir: Output directory
        seed: Random seed
        
    Returns:
        LOFO results dict
    """
    df = pd.read_csv(dataset_path)
    families = ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10']
    
    results = {}
    
    for held_out_family in families:
        print(f"\nLOFO: Holding out {held_out_family}...")
        
        # Create temp datasets
        train_mask = (df['split'] == 'train') & (df['family'] != held_out_family)
        val_mask = (df['split'] == 'validation') & (df['family'] != held_out_family)
        test_mask = df['family'] == held_out_family
        
        if test_mask.sum() == 0:
            continue
        
        # Combine train+val for LOFO
        lofo_train_df = df[train_mask | val_mask].copy()
        lofo_train_df['split'] = 'train'
        
        # Use a small val split from the training data
        val_indices = lofo_train_df.sample(frac=0.15, random_state=seed).index
        lofo_train_df.loc[val_indices, 'split'] = 'validation'
        
        lofo_test_df = df[test_mask].copy()
        lofo_test_df['split'] = 'test'
        
        lofo_df = pd.concat([lofo_train_df, lofo_test_df])
        
        # Train model
        temp_dataset = Path(output_dir) / f'lofo_{held_out_family}_temp.csv'
        lofo_df.to_csv(temp_dataset, index=False)
        
        model = PCDModel()
        model.train(str(temp_dataset), seed=seed)
        
        # Evaluate on held-out family
        test_codes = lofo_test_df['code'].values
        test_labels = lofo_test_df['label'].values
        
        scores = []
        for code in test_codes:
            score, _ = model.predict(code)
            scores.append(score)
        
        scores = np.array(scores)
        preds = (scores >= model.malicious_threshold).astype(int)
        
        if test_labels.sum() > 0:  # If there are any malicious samples
            recall = recall_score(test_labels, preds)
        else:
            recall = 0.0
        
        results[held_out_family] = recall
        
        # Clean up
        temp_dataset.unlink()
    
    # Calculate mean
    mean_recall = np.mean(list(results.values()))
    results['mean_recall'] = mean_recall
    
    # Save results
    output_path = Path(output_dir)
    with open(output_path / 'lofo_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nLOFO Mean Recall: {mean_recall:.3f}")
    
    return results
