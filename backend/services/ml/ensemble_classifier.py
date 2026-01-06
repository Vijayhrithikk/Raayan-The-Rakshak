"""
Ensemble Classifier for Production IDS
Combines multiple ML models for robust intrusion detection.

Uses voting/stacking ensemble of:
- Random Forest (feature-based)
- XGBoost (gradient boosting)
- Isolation Forest (anomaly detection)
- Neural Network (pattern recognition)
"""
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import pickle
import os
import warnings

# Suppress sklearn warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier, IsolationForest, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# XGBoost (optional - fallback to RandomForest if not available)
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    XGBClassifier = None


class AttackType(Enum):
    """Attack types the ensemble can classify"""
    BENIGN = "benign"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    ICMP_FLOOD = "icmp_flood"
    LATERAL_MOVEMENT = "lateral_movement"
    POLICY_VIOLATION = "policy_violation"
    DATA_EXFILTRATION = "data_exfiltration"
    C2_BEACON = "c2_beacon"
    DNS_TUNNELING = "dns_tunneling"
    ARP_SPOOF = "arp_spoof"


@dataclass
class EnsemblePrediction:
    """Prediction result from ensemble classifier"""
    attack_type: str
    confidence: float
    is_attack: bool
    
    # Individual model votes
    rf_prediction: str
    rf_confidence: float
    xgb_prediction: Optional[str]
    xgb_confidence: Optional[float]
    isolation_score: float  # -1 = anomaly, 1 = normal
    
    # Feature importance for this prediction
    top_features: List[Tuple[str, float]] = field(default_factory=list)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    model_version: str = "1.0.0"


class EnsembleClassifier:
    """
    Production Ensemble Classifier for Network Intrusion Detection.
    
    Combines multiple ML approaches:
    1. Random Forest - Excellent for tabular data, handles mixed features
    2. XGBoost - Gradient boosting for high accuracy
    3. Isolation Forest - Anomaly detection for unknown attacks
    4. Meta-classifier (Logistic Regression) - Stacks predictions
    
    The ensemble uses soft voting with calibrated probabilities and
    can detect both known attack patterns and zero-day anomalies.
    """
    
    MODEL_VERSION = "1.0.0"
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        # Feature preprocessing
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Attack type labels
        self.attack_labels = [at.value for at in AttackType]
        self.label_encoder.fit(self.attack_labels)
        
        # Initialize models
        self.rf_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            n_jobs=-1,
            random_state=42,
            class_weight='balanced'
        )
        
        if XGBOOST_AVAILABLE:
            self.xgb_classifier = XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss',
                use_label_encoder=False
            )
        else:
            # Fallback to extra RandomForest
            self.xgb_classifier = RandomForestClassifier(
                n_estimators=150,
                max_depth=15,
                random_state=43,
                n_jobs=-1
            )
        
        # Anomaly detector for zero-day attacks
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # Expect 5% anomalies
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        # Meta-classifier for stacking
        self.meta_classifier = LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=42
        )
        
        # Training state
        self.is_trained = False
        self.feature_names: List[str] = []
        self.training_metrics: Dict[str, Any] = {}
    
    def fit(self, X: np.ndarray, y: np.ndarray, 
            feature_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Train the ensemble on labeled data.
        
        Args:
            X: Feature array of shape (n_samples, n_features)
            y: Labels array of shape (n_samples,) with attack type strings
            feature_names: Optional list of feature names for explainability
            
        Returns:
            Dictionary of training metrics
        """
        if len(X) < 10:
            raise ValueError("Need at least 10 samples to train")
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        
        # Preprocess
        X_scaled = self.scaler.fit_transform(X)
        y_encoded = self.label_encoder.transform(y)
        
        # Split for validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Train individual models
        print("Training Random Forest...")
        self.rf_classifier.fit(X_train, y_train)
        rf_score = self.rf_classifier.score(X_val, y_val)
        
        print("Training XGBoost..." if XGBOOST_AVAILABLE else "Training secondary RF...")
        self.xgb_classifier.fit(X_train, y_train)
        xgb_score = self.xgb_classifier.score(X_val, y_val)
        
        print("Training Isolation Forest...")
        self.isolation_forest.fit(X_train)
        
        # Train meta-classifier using stacking
        print("Training meta-classifier...")
        rf_probs = self.rf_classifier.predict_proba(X_val)
        xgb_probs = self.xgb_classifier.predict_proba(X_val)
        iso_scores = self.isolation_forest.score_samples(X_val).reshape(-1, 1)
        
        meta_features = np.hstack([rf_probs, xgb_probs, iso_scores])
        self.meta_classifier.fit(meta_features, y_val)
        meta_score = self.meta_classifier.score(meta_features, y_val)
        
        self.is_trained = True
        
        # Compute detailed metrics
        y_pred = self._predict_ensemble(X_val)
        
        self.training_metrics = {
            'rf_accuracy': rf_score,
            'xgb_accuracy': xgb_score,
            'meta_accuracy': meta_score,
            'n_samples': len(X),
            'n_features': X.shape[1],
            'n_classes': len(np.unique(y)),
            'trained_at': datetime.now().isoformat()
        }
        
        print(f"\nTraining Complete!")
        print(f"  Random Forest: {rf_score:.2%}")
        print(f"  XGBoost: {xgb_score:.2%}")
        print(f"  Meta-classifier: {meta_score:.2%}")
        
        return self.training_metrics
    
    def predict(self, X: np.ndarray) -> List[EnsemblePrediction]:
        """
        Make predictions using the ensemble.
        
        Args:
            X: Feature array of shape (n_samples, n_features)
            
        Returns:
            List of EnsemblePrediction objects
        """
        if not self.is_trained:
            # Return anomaly-based predictions only
            return self._predict_anomaly_only(X)
        
        return self._predict_ensemble(X)
    
    def predict_single(self, features: np.ndarray) -> EnsemblePrediction:
        """Predict for a single sample"""
        if features.ndim == 1:
            features = features.reshape(1, -1)
        return self.predict(features)[0]
    
    def _predict_ensemble(self, X: np.ndarray) -> List[EnsemblePrediction]:
        """Full ensemble prediction with all models"""
        X_scaled = self.scaler.transform(X)
        
        # Get individual predictions
        rf_probs = self.rf_classifier.predict_proba(X_scaled)
        rf_preds = self.rf_classifier.predict(X_scaled)
        
        xgb_probs = self.xgb_classifier.predict_proba(X_scaled)
        xgb_preds = self.xgb_classifier.predict(X_scaled)
        
        iso_scores = self.isolation_forest.score_samples(X_scaled)
        
        # Meta-classifier stacking
        meta_features = np.hstack([rf_probs, xgb_probs, iso_scores.reshape(-1, 1)])
        final_preds = self.meta_classifier.predict(meta_features)
        final_probs = self.meta_classifier.predict_proba(meta_features)
        
        predictions = []
        for i in range(len(X)):
            attack_type = self.label_encoder.inverse_transform([final_preds[i]])[0]
            confidence = float(np.max(final_probs[i]))
            
            # Get RF and XGB individual results
            rf_type = self.label_encoder.inverse_transform([rf_preds[i]])[0]
            rf_conf = float(np.max(rf_probs[i]))
            xgb_type = self.label_encoder.inverse_transform([xgb_preds[i]])[0]
            xgb_conf = float(np.max(xgb_probs[i]))
            
            # Get top contributing features
            top_features = self._get_top_features(X_scaled[i], 5)
            
            pred = EnsemblePrediction(
                attack_type=attack_type,
                confidence=confidence,
                is_attack=(attack_type != 'benign'),
                rf_prediction=rf_type,
                rf_confidence=rf_conf,
                xgb_prediction=xgb_type,
                xgb_confidence=xgb_conf,
                isolation_score=float(iso_scores[i]),
                top_features=top_features,
                model_version=self.MODEL_VERSION
            )
            predictions.append(pred)
        
        return predictions
    
    def _predict_anomaly_only(self, X: np.ndarray) -> List[EnsemblePrediction]:
        """Fallback prediction using only anomaly detection (when not trained)"""
        # Fit isolation forest on-the-fly if needed
        if not hasattr(self, '_isolation_fitted'):
            self.isolation_forest.fit(X)
            self._isolation_fitted = True
        
        iso_preds = self.isolation_forest.predict(X)
        iso_scores = self.isolation_forest.score_samples(X)
        
        predictions = []
        for i in range(len(X)):
            is_anomaly = iso_preds[i] == -1
            
            pred = EnsemblePrediction(
                attack_type='unknown_anomaly' if is_anomaly else 'benign',
                confidence=abs(float(iso_scores[i])),
                is_attack=is_anomaly,
                rf_prediction='unknown',
                rf_confidence=0.0,
                xgb_prediction=None,
                xgb_confidence=None,
                isolation_score=float(iso_scores[i]),
                model_version=self.MODEL_VERSION
            )
            predictions.append(pred)
        
        return predictions
    
    def _get_top_features(self, sample: np.ndarray, k: int = 5) -> List[Tuple[str, float]]:
        """Get top k contributing features for a prediction"""
        if not self.is_trained or not self.feature_names:
            return []
        
        # Use RF feature importances weighted by sample values
        importances = self.rf_classifier.feature_importances_
        weighted = importances * np.abs(sample)
        
        top_indices = np.argsort(weighted)[-k:][::-1]
        
        return [
            (self.feature_names[i], float(weighted[i]))
            for i in top_indices
        ]
    
    def get_feature_importances(self) -> Dict[str, float]:
        """Get overall feature importances from Random Forest"""
        if not self.is_trained:
            return {}
        
        importances = self.rf_classifier.feature_importances_
        return {
            name: float(imp)
            for name, imp in zip(self.feature_names, importances)
        }
    
    def save(self, path: Optional[str] = None) -> str:
        """Save ensemble to disk"""
        if path is None:
            path = os.path.join(self.model_dir, f"ensemble_v{self.MODEL_VERSION}.pkl")
        
        state = {
            'rf': self.rf_classifier,
            'xgb': self.xgb_classifier,
            'iso': self.isolation_forest,
            'meta': self.meta_classifier,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'metrics': self.training_metrics,
            'version': self.MODEL_VERSION
        }
        
        with open(path, 'wb') as f:
            pickle.dump(state, f)
        
        return path
    
    def load(self, path: str) -> None:
        """Load ensemble from disk"""
        with open(path, 'rb') as f:
            state = pickle.load(f)
        
        self.rf_classifier = state['rf']
        self.xgb_classifier = state['xgb']
        self.isolation_forest = state['iso']
        self.meta_classifier = state['meta']
        self.scaler = state['scaler']
        self.label_encoder = state['label_encoder']
        self.feature_names = state['feature_names']
        self.is_trained = state['is_trained']
        self.training_metrics = state['metrics']
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model metadata for monitoring"""
        return {
            'version': self.MODEL_VERSION,
            'is_trained': self.is_trained,
            'n_features': len(self.feature_names),
            'xgboost_available': XGBOOST_AVAILABLE,
            'attack_types': self.attack_labels,
            'training_metrics': self.training_metrics
        }
