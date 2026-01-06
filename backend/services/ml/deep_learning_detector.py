"""
Deep Learning Detector for Production IDS
Implements LSTM/GRU-based sequence analysis for temporal attack patterns.

Uses TensorFlow/Keras for neural network models with fallback
to scikit-learn MLPClassifier when TensorFlow is not available.
"""
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
import warnings

warnings.filterwarnings('ignore')

# Try to import TensorFlow/Keras
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import (
        LSTM, GRU, Dense, Dropout, Bidirectional, 
        Input, Attention, Concatenate, BatchNormalization
    )
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
    from tensorflow.keras.optimizers import Adam
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

# Fallback to sklearn MLP
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler


# Attack labels matching ensemble classifier
ATTACK_LABELS = [
    'benign', 'port_scan', 'brute_force', 'icmp_flood',
    'lateral_movement', 'policy_violation', 'data_exfiltration',
    'c2_beacon', 'dns_tunneling', 'arp_spoof'
]


@dataclass
class SequenceWindow:
    """A window of network flows for sequence analysis"""
    flows: List[np.ndarray]
    timestamps: List[datetime]
    source_ip: str
    window_id: str
    
    def to_array(self) -> np.ndarray:
        """Convert to 3D array for LSTM: (1, seq_len, features)"""
        if not self.flows:
            return np.zeros((1, 1, 47))  # Default 47 features
        return np.array([self.flows])


@dataclass
class DLPrediction:
    """Prediction from deep learning model"""
    attack_type: str
    confidence: float
    is_attack: bool
    sequence_score: float  # How suspicious is the sequence pattern
    
    # Attention weights (if available)
    attention_weights: Optional[np.ndarray] = None
    
    # Which flows in sequence were most suspicious
    suspicious_indices: List[int] = field(default_factory=list)
    
    timestamp: datetime = field(default_factory=datetime.now)


class DeepLearningDetector:
    """
    Deep Learning Detector for Temporal Attack Patterns.
    
    Uses bidirectional LSTM with attention to analyze sequences
    of network flows and detect:
    - Port scanning patterns
    - Brute force attempts with timing patterns
    - C2 beaconing (periodic connections)
    - Data exfiltration (unusual data flow patterns)
    
    Falls back to MLP classifier when TensorFlow unavailable.
    """
    
    # Model parameters
    SEQUENCE_LENGTH = 20  # Number of flows in a sequence
    NUM_FEATURES = 47     # Feature dimensions per flow
    HIDDEN_UNITS = 128    # LSTM hidden units
    NUM_CLASSES = len(ATTACK_LABELS)
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.is_trained = False
        self.using_tensorflow = TF_AVAILABLE
        
        # Feature scaler
        self.scaler = StandardScaler()
        
        # Initialize model
        if TF_AVAILABLE:
            self.model = self._build_lstm_model()
        else:
            self.model = self._build_mlp_fallback()
        
        # Sequence buffers per source IP
        self.sequence_buffers: Dict[str, deque] = {}
        self.buffer_size = self.SEQUENCE_LENGTH
        
        # Label mapping
        self.label_to_idx = {label: i for i, label in enumerate(ATTACK_LABELS)}
        self.idx_to_label = {i: label for i, label in enumerate(ATTACK_LABELS)}
        
    def _build_lstm_model(self) -> Any:
        """Build bidirectional LSTM with attention"""
        if not TF_AVAILABLE:
            return None
            
        # Input layer
        inputs = Input(shape=(self.SEQUENCE_LENGTH, self.NUM_FEATURES))
        
        # Bidirectional LSTM layers
        x = Bidirectional(LSTM(self.HIDDEN_UNITS, return_sequences=True))(inputs)
        x = Dropout(0.3)(x)
        x = BatchNormalization()(x)
        
        # Second LSTM layer
        x = Bidirectional(LSTM(64, return_sequences=True))(x)
        x = Dropout(0.2)(x)
        
        # Simple attention mechanism
        attention = Dense(1, activation='tanh')(x)
        attention = tf.keras.layers.Flatten()(attention)
        attention = tf.keras.layers.Activation('softmax')(attention)
        attention = tf.keras.layers.RepeatVector(128)(attention)
        attention = tf.keras.layers.Permute([2, 1])(attention)
        
        # Apply attention
        x = tf.keras.layers.Multiply()([x, attention])
        x = tf.keras.layers.Lambda(lambda x: tf.reduce_sum(x, axis=1))(x)
        
        # Dense layers
        x = Dense(64, activation='relu')(x)
        x = Dropout(0.2)(x)
        x = Dense(32, activation='relu')(x)
        
        # Output
        outputs = Dense(self.NUM_CLASSES, activation='softmax')(x)
        
        model = Model(inputs=inputs, outputs=outputs)
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _build_mlp_fallback(self) -> MLPClassifier:
        """Build MLP classifier as fallback"""
        return MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.0001,
            batch_size='auto',
            learning_rate='adaptive',
            max_iter=500,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1
        )
    
    def add_flow_to_buffer(self, source_ip: str, features: np.ndarray, 
                           timestamp: datetime) -> Optional[SequenceWindow]:
        """
        Add a flow to the sequence buffer for a source IP.
        Returns a SequenceWindow when buffer is full.
        
        Args:
            source_ip: Source IP address
            features: Feature vector for this flow
            timestamp: Flow timestamp
            
        Returns:
            SequenceWindow if buffer is full, None otherwise
        """
        if source_ip not in self.sequence_buffers:
            self.sequence_buffers[source_ip] = deque(maxlen=self.buffer_size)
        
        self.sequence_buffers[source_ip].append((features, timestamp))
        
        # Return window when full
        if len(self.sequence_buffers[source_ip]) >= self.buffer_size:
            flows = [f[0] for f in self.sequence_buffers[source_ip]]
            timestamps = [f[1] for f in self.sequence_buffers[source_ip]]
            
            return SequenceWindow(
                flows=flows,
                timestamps=timestamps,
                source_ip=source_ip,
                window_id=f"{source_ip}_{timestamp.timestamp()}"
            )
        
        return None
    
    def fit(self, X: np.ndarray, y: np.ndarray, 
            epochs: int = 50, batch_size: int = 32) -> Dict[str, Any]:
        """
        Train the deep learning model.
        
        Args:
            X: Sequence data of shape (n_sequences, seq_length, n_features)
            y: Labels of shape (n_sequences,) with attack type strings
            epochs: Training epochs
            batch_size: Batch size
            
        Returns:
            Training history/metrics
        """
        # Convert labels to indices
        y_idx = np.array([self.label_to_idx.get(label, 0) for label in y])
        
        if self.using_tensorflow:
            # One-hot encode labels
            y_onehot = tf.keras.utils.to_categorical(y_idx, self.NUM_CLASSES)
            
            # Callbacks
            callbacks = [
                EarlyStopping(patience=10, restore_best_weights=True),
            ]
            
            # Train
            history = self.model.fit(
                X, y_onehot,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                callbacks=callbacks,
                verbose=1
            )
            
            self.is_trained = True
            
            return {
                'final_loss': history.history['loss'][-1],
                'final_accuracy': history.history['accuracy'][-1],
                'val_accuracy': history.history.get('val_accuracy', [0])[-1],
                'epochs_trained': len(history.history['loss']),
                'using_tensorflow': True
            }
        else:
            # Flatten sequences for MLP
            X_flat = X.reshape(X.shape[0], -1)
            self.scaler.fit(X_flat)
            X_scaled = self.scaler.transform(X_flat)
            
            self.model.fit(X_scaled, y_idx)
            self.is_trained = True
            
            return {
                'using_tensorflow': False,
                'n_samples': len(X),
                'n_features': X_flat.shape[1]
            }
    
    def predict_sequence(self, sequence: SequenceWindow) -> DLPrediction:
        """
        Predict attack type for a sequence of flows.
        
        Args:
            sequence: SequenceWindow containing flow features
            
        Returns:
            DLPrediction with attack type and confidence
        """
        X = sequence.to_array()
        
        # Pad if needed
        if X.shape[1] < self.SEQUENCE_LENGTH:
            padding = np.zeros((1, self.SEQUENCE_LENGTH - X.shape[1], self.NUM_FEATURES))
            X = np.concatenate([X, padding], axis=1)
        
        if self.using_tensorflow and self.is_trained:
            probs = self.model.predict(X, verbose=0)[0]
            pred_idx = np.argmax(probs)
            confidence = float(probs[pred_idx])
            
            # Get attention weights if available (simplified)
            attention_weights = self._get_attention_approximation(X[0])
            suspicious_indices = self._find_suspicious_flows(attention_weights)
            
        elif self.is_trained:
            X_flat = X.reshape(1, -1)
            X_scaled = self.scaler.transform(X_flat)
            pred_idx = self.model.predict(X_scaled)[0]
            probs = self.model.predict_proba(X_scaled)[0]
            confidence = float(np.max(probs))
            attention_weights = None
            suspicious_indices = []
        else:
            # No training - use heuristics
            return self._predict_heuristic(sequence)
        
        attack_type = self.idx_to_label.get(pred_idx, 'benign')
        
        return DLPrediction(
            attack_type=attack_type,
            confidence=confidence,
            is_attack=(attack_type != 'benign'),
            sequence_score=confidence if attack_type != 'benign' else 1 - confidence,
            attention_weights=attention_weights,
            suspicious_indices=suspicious_indices
        )
    
    def predict_flows(self, features: np.ndarray) -> List[DLPrediction]:
        """
        Predict for multiple individual flows (not sequences).
        Creates sliding windows automatically.
        
        Args:
            features: Array of shape (n_flows, n_features)
            
        Returns:
            List of predictions (one per window)
        """
        predictions = []
        
        if len(features) < self.SEQUENCE_LENGTH:
            # Pad single window
            padded = np.zeros((self.SEQUENCE_LENGTH, self.NUM_FEATURES))
            padded[:len(features)] = features
            
            window = SequenceWindow(
                flows=list(features),
                timestamps=[datetime.now()] * len(features),
                source_ip='batch',
                window_id='batch_0'
            )
            predictions.append(self.predict_sequence(window))
        else:
            # Sliding windows
            for i in range(0, len(features) - self.SEQUENCE_LENGTH + 1, self.SEQUENCE_LENGTH // 2):
                window_features = features[i:i + self.SEQUENCE_LENGTH]
                window = SequenceWindow(
                    flows=list(window_features),
                    timestamps=[datetime.now()] * self.SEQUENCE_LENGTH,
                    source_ip='batch',
                    window_id=f'batch_{i}'
                )
                predictions.append(self.predict_sequence(window))
        
        return predictions
    
    def _predict_heuristic(self, sequence: SequenceWindow) -> DLPrediction:
        """Heuristic-based prediction when model is not trained"""
        flows = sequence.flows
        
        if not flows:
            return DLPrediction(
                attack_type='benign',
                confidence=0.5,
                is_attack=False,
                sequence_score=0.0
            )
        
        # Simple heuristics based on flow patterns
        features = np.array(flows)
        
        # Check for port scan pattern (many unique ports)
        unique_ports = len(np.unique(features[:, 4] if features.shape[1] > 4 else [0]))
        if unique_ports > 10:
            return DLPrediction(
                attack_type='port_scan',
                confidence=0.7,
                is_attack=True,
                sequence_score=0.7,
                suspicious_indices=list(range(len(flows)))
            )
        
        # Check for high packet rate (ICMP flood)
        if features.shape[1] > 14:
            avg_pkt_rate = np.mean(features[:, 14])
            if avg_pkt_rate > 100:
                return DLPrediction(
                    attack_type='icmp_flood',
                    confidence=0.6,
                    is_attack=True,
                    sequence_score=0.6
                )
        
        # Check for periodic patterns (C2 beacon)
        if len(sequence.timestamps) >= 5:
            intervals = []
            for i in range(1, len(sequence.timestamps)):
                delta = (sequence.timestamps[i] - sequence.timestamps[i-1]).total_seconds()
                intervals.append(delta)
            
            if intervals:
                interval_std = np.std(intervals)
                if interval_std < 1.0 and np.mean(intervals) > 10:
                    return DLPrediction(
                        attack_type='c2_beacon',
                        confidence=0.65,
                        is_attack=True,
                        sequence_score=0.65
                    )
        
        return DLPrediction(
            attack_type='benign',
            confidence=0.6,
            is_attack=False,
            sequence_score=0.0
        )
    
    def _get_attention_approximation(self, sequence: np.ndarray) -> np.ndarray:
        """Approximate attention weights based on feature variance"""
        # Higher variance in features = more attention
        variances = np.var(sequence, axis=1)
        # Normalize to sum to 1
        if variances.sum() > 0:
            return variances / variances.sum()
        return np.ones(len(sequence)) / len(sequence)
    
    def _find_suspicious_flows(self, attention_weights: np.ndarray, 
                                threshold: float = 0.1) -> List[int]:
        """Find indices of flows with high attention"""
        if attention_weights is None:
            return []
        return [i for i, w in enumerate(attention_weights) if w > threshold]
    
    def save(self, path: str) -> None:
        """Save model to disk"""
        if self.using_tensorflow and self.is_trained:
            self.model.save(path)
        elif self.is_trained:
            import pickle
            with open(path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler
                }, f)
    
    def load(self, path: str) -> None:
        """Load model from disk"""
        if self.using_tensorflow:
            self.model = tf.keras.models.load_model(path)
            self.is_trained = True
        else:
            import pickle
            with open(path, 'rb') as f:
                state = pickle.load(f)
                self.model = state['model']
                self.scaler = state['scaler']
                self.is_trained = True
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model metadata"""
        info = {
            'using_tensorflow': self.using_tensorflow,
            'is_trained': self.is_trained,
            'sequence_length': self.SEQUENCE_LENGTH,
            'num_features': self.NUM_FEATURES,
            'num_classes': self.NUM_CLASSES,
            'attack_types': ATTACK_LABELS
        }
        
        if self.using_tensorflow and self.model:
            info['model_type'] = 'Bidirectional LSTM with Attention'
            info['total_params'] = self.model.count_params() if hasattr(self.model, 'count_params') else 'N/A'
        else:
            info['model_type'] = 'sklearn MLPClassifier'
        
        return info

