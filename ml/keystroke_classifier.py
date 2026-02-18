#!/usr/bin/env python3
"""
Keystroke Dynamics Classifier - Distinguishes humans from bots
Uses scikit-learn to analyze keystroke timing patterns
"""

import numpy as np
import pickle
import os
import json
import logging
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from collections import deque

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)


class KeystrokeFeatureExtractor:
    """Extract features from keystroke timing data"""
    
    @staticmethod
    def extract_features(keystroke_timings: List[Dict]) -> Dict[str, float]:
        """
        Extract statistical features from keystroke timing data
        
        Key insight: Bots tend to have very consistent timing (<50ms)
        Humans have variable timing with natural patterns
        """
        if not keystroke_timings or len(keystroke_timings) < 3:
            return None
        
        # Extract intervals in milliseconds
        intervals = [kt['interval_ms'] for kt in keystroke_timings 
                     if kt.get('interval_ms') is not None and kt['interval_ms'] > 0]
        
        if len(intervals) < 3:
            return None
        
        intervals = np.array(intervals)
        
        # Basic statistics
        features = {
            'mean_interval': np.mean(intervals),
            'std_interval': np.std(intervals),
            'median_interval': np.median(intervals),
            'min_interval': np.min(intervals),
            'max_interval': np.max(intervals),
            'range_interval': np.max(intervals) - np.min(intervals),
            
            # Coefficient of variation (normalized std)
            'cv_interval': np.std(intervals) / np.mean(intervals) if np.mean(intervals) > 0 else 0,
            
            # Percentiles
            'p25_interval': np.percentile(intervals, 25),
            'p75_interval': np.percentile(intervals, 75),
            'p90_interval': np.percentile(intervals, 90),
            'p95_interval': np.percentile(intervals, 95),
            'p99_interval': np.percentile(intervals, 99),
            
            # Interquartile range
            'iqr_interval': np.percentile(intervals, 75) - np.percentile(intervals, 25),
            
            # Skewness and kurtosis (shape of distribution)
            'skewness': KeystrokeFeatureExtractor._skewness(intervals),
            'kurtosis': KeystrokeFeatureExtractor._kurtosis(intervals),
            
            # Count of very fast keystrokes (bot indicator)
            'fast_keystrokes_count': np.sum(intervals < 50),
            'fast_keystrokes_ratio': np.sum(intervals < 50) / len(intervals),
            
            # Count of slow keystrokes (human indicator)
            'slow_keystrokes_count': np.sum(intervals > 200),
            'slow_keystrokes_ratio': np.sum(intervals > 200) / len(intervals),
            
            # Very consistent timing (bot indicator)
            'very_consistent': 1 if np.std(intervals) < 10 else 0,
            
            # Number of keystrokes
            'keystroke_count': len(intervals),
            
            # Ratio of intervals in different ranges
            'ratio_0_50ms': np.sum((intervals >= 0) & (intervals < 50)) / len(intervals),
            'ratio_50_100ms': np.sum((intervals >= 50) & (intervals < 100)) / len(intervals),
            'ratio_100_200ms': np.sum((intervals >= 100) & (intervals < 200)) / len(intervals),
            'ratio_200_500ms': np.sum((intervals >= 200) & (intervals < 500)) / len(intervals),
            'ratio_500_plus': np.sum(intervals >= 500) / len(intervals),
            
            # Autocorrelation (pattern detection)
            'autocorr_lag1': KeystrokeFeatureExtractor._autocorrelation(intervals, lag=1),
            'autocorr_lag2': KeystrokeFeatureExtractor._autocorrelation(intervals, lag=2),
            
            # Trend (increasing/decreasing intervals)
            'trend_slope': KeystrokeFeatureExtractor._linear_trend(intervals),
            
            # Burst detection (clusters of fast typing)
            'burst_count': KeystrokeFeatureExtractor._count_bursts(intervals),
            'avg_burst_length': KeystrokeFeatureExtractor._avg_burst_length(intervals),
        }
        
        return features
    
    @staticmethod
    def _skewness(data: np.ndarray) -> float:
        """Calculate skewness of data"""
        if len(data) < 3:
            return 0
        mean = np.mean(data)
        std = np.std(data)
        if std == 0:
            return 0
        return np.mean(((data - mean) / std) ** 3)
    
    @staticmethod
    def _kurtosis(data: np.ndarray) -> float:
        """Calculate excess kurtosis of data"""
        if len(data) < 4:
            return 0
        mean = np.mean(data)
        std = np.std(data)
        if std == 0:
            return 0
        return np.mean(((data - mean) / std) ** 4) - 3
    
    @staticmethod
    def _autocorrelation(data: np.ndarray, lag: int = 1) -> float:
        """Calculate autocorrelation at given lag"""
        if len(data) <= lag:
            return 0
        
        mean = np.mean(data)
        c0 = np.sum((data - mean) ** 2) / len(data)
        
        if c0 == 0:
            return 0
        
        c_lag = np.sum((data[:-lag] - mean) * (data[lag:] - mean)) / len(data)
        return c_lag / c0
    
    @staticmethod
    def _linear_trend(data: np.ndarray) -> float:
        """Calculate linear trend slope"""
        if len(data) < 2:
            return 0
        x = np.arange(len(data))
        return np.polyfit(x, data, 1)[0]
    
    @staticmethod
    def _count_bursts(data: np.ndarray, threshold_ms: float = 100) -> int:
        """Count number of typing bursts (consecutive fast keystrokes)"""
        if len(data) == 0:
            return 0
        
        in_burst = False
        burst_count = 0
        
        for interval in data:
            if interval < threshold_ms:
                if not in_burst:
                    burst_count += 1
                    in_burst = True
            else:
                in_burst = False
        
        return burst_count
    
    @staticmethod
    def _avg_burst_length(data: np.ndarray, threshold_ms: float = 100) -> float:
        """Calculate average length of typing bursts"""
        if len(data) == 0:
            return 0
        
        burst_lengths = []
        current_length = 0
        
        for interval in data:
            if interval < threshold_ms:
                current_length += 1
            else:
                if current_length > 0:
                    burst_lengths.append(current_length)
                    current_length = 0
        
        if current_length > 0:
            burst_lengths.append(current_length)
        
        return np.mean(burst_lengths) if burst_lengths else 0


class HumanBotClassifier:
    """
    Classifier to distinguish between human attackers and automated bots/scripts
    
    Key characteristics:
    - Bots: Very consistent timing (<50ms), low variance, predictable patterns
    - Humans: Variable timing, higher variance, natural typing patterns
    """
    
    MODEL_PATH = '/app/data/keystroke_classifier.pkl'
    SCALER_PATH = '/app/data/keystroke_scaler.pkl'
    
    # Feature names for the model
    FEATURE_NAMES = [
        'mean_interval', 'std_interval', 'median_interval', 'min_interval', 'max_interval',
        'range_interval', 'cv_interval', 'p25_interval', 'p75_interval', 'p90_interval',
        'p95_interval', 'p99_interval', 'iqr_interval', 'skewness', 'kurtosis',
        'fast_keystrokes_count', 'fast_keystrokes_ratio', 'slow_keystrokes_count',
        'slow_keystrokes_ratio', 'very_consistent', 'keystroke_count',
        'ratio_0_50ms', 'ratio_50_100ms', 'ratio_100_200ms', 'ratio_200_500ms',
        'ratio_500_plus', 'autocorr_lag1', 'autocorr_lag2', 'trend_slope',
        'burst_count', 'avg_burst_length'
    ]
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.training_history = deque(maxlen=1000)  # Store recent predictions for retraining
        self._load_or_initialize_model()
    
    def _load_or_initialize_model(self):
        """Load existing model or initialize a new one"""
        try:
            if os.path.exists(self.MODEL_PATH) and os.path.exists(self.SCALER_PATH):
                with open(self.MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.is_trained = True
                logger.info("Loaded existing keystroke classifier model")
            else:
                self._initialize_new_model()
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self._initialize_new_model()
    
    def _initialize_new_model(self):
        """Initialize a new untrained model"""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        logger.info("Initialized new keystroke classifier model")
    
    def _features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy array"""
        return np.array([features.get(name, 0) for name in self.FEATURE_NAMES]).reshape(1, -1)
    
    def generate_synthetic_training_data(self, n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic training data for initial model training
        
        Simulates both bot and human keystroke patterns
        """
        np.random.seed(42)
        
        features_list = []
        labels = []
        
        # Generate bot samples (consistent, fast timing)
        for _ in range(n_samples // 2):
            # Bots have very consistent timing, mostly <50ms
            base_interval = np.random.uniform(10, 50)
            n_keystrokes = np.random.randint(20, 200)
            
            # Add small noise
            intervals = np.random.normal(base_interval, base_interval * 0.1, n_keystrokes)
            intervals = np.clip(intervals, 5, 100)
            
            keystrokes = [{'interval_ms': iv} for iv in intervals]
            features = KeystrokeFeatureExtractor.extract_features(keystrokes)
            
            if features:
                features_list.append([features.get(name, 0) for name in self.FEATURE_NAMES])
                labels.append(1)  # 1 = bot
        
        # Generate human samples (variable timing)
        for _ in range(n_samples // 2):
            # Humans have variable timing with natural patterns
            n_keystrokes = np.random.randint(20, 200)
            intervals = []
            
            # Simulate typing bursts and pauses
            current_pattern = 'typing'  # 'typing' or 'thinking'
            
            for _ in range(n_keystrokes):
                if current_pattern == 'typing':
                    # Fast typing: 50-150ms
                    interval = np.random.uniform(50, 150)
                    # Occasionally switch to thinking
                    if np.random.random() < 0.05:
                        current_pattern = 'thinking'
                else:
                    # Thinking/pausing: 200-1000ms
                    interval = np.random.uniform(200, 1000)
                    # Switch back to typing
                    current_pattern = 'typing'
                
                intervals.append(interval)
            
            keystrokes = [{'interval_ms': iv} for iv in intervals]
            features = KeystrokeFeatureExtractor.extract_features(keystrokes)
            
            if features:
                features_list.append([features.get(name, 0) for name in self.FEATURE_NAMES])
                labels.append(0)  # 0 = human
        
        return np.array(features_list), np.array(labels)
    
    def train(self, X: Optional[np.ndarray] = None, y: Optional[np.ndarray] = None,
              validation_split: float = 0.2) -> Dict:
        """
        Train the classifier
        
        If no data provided, generates synthetic training data
        """
        try:
            if X is None or y is None:
                logger.info("Generating synthetic training data...")
                X, y = self.generate_synthetic_training_data(n_samples=2000)
            
            # Split data
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=validation_split, random_state=42, stratify=y
            )
            
            # Fit scaler and transform data
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            X_val_scaled = self.scaler.transform(X_val)
            
            # Train model
            logger.info("Training RandomForest classifier...")
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            train_pred = self.model.predict(X_train_scaled)
            val_pred = self.model.predict(X_val_scaled)
            
            train_accuracy = accuracy_score(y_train, train_pred)
            val_accuracy = accuracy_score(y_val, val_pred)
            
            # Cross-validation
            cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
            
            # Feature importance
            feature_importance = dict(zip(
                self.FEATURE_NAMES,
                self.model.feature_importances_
            ))
            top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
            
            self.is_trained = True
            
            # Save model
            self._save_model()
            
            results = {
                'train_accuracy': train_accuracy,
                'validation_accuracy': val_accuracy,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'top_features': top_features,
                'confusion_matrix': confusion_matrix(y_val, val_pred).tolist(),
                'classification_report': classification_report(y_val, val_pred, 
                                                               target_names=['human', 'bot'])
            }
            
            logger.info(f"Training complete. Validation accuracy: {val_accuracy:.4f}")
            return results
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return {'error': str(e)}
    
    def classify(self, keystroke_timings: List[Dict]) -> Dict:
        """
        Classify a session as human or bot based on keystroke timings
        
        Returns:
            Dict with classification result and confidence
        """
        if not self.is_trained:
            logger.warning("Model not trained, using rule-based classification")
            return self._rule_based_classify(keystroke_timings)
        
        try:
            features = KeystrokeFeatureExtractor.extract_features(keystroke_timings)
            
            if features is None:
                return {
                    'classification': 'unknown',
                    'confidence': 0.0,
                    'human_probability': 0.5,
                    'bot_probability': 0.5,
                    'reason': 'insufficient_data'
                }
            
            # Convert to feature vector
            X = self._features_to_vector(features)
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            human_prob = probabilities[0]
            bot_prob = probabilities[1]
            
            # Determine classification
            if prediction == 0:
                classification = 'human'
                confidence = human_prob
            else:
                classification = 'bot'
                confidence = bot_prob
            
            result = {
                'classification': classification,
                'confidence': confidence,
                'human_probability': human_prob,
                'bot_probability': bot_prob,
                'features': {k: round(v, 4) for k, v in features.items()},
                'top_indicators': self._get_top_indicators(features, classification)
            }
            
            # Store for potential retraining
            self.training_history.append({
                'features': features,
                'prediction': classification,
                'confidence': confidence
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error during classification: {e}")
            return self._rule_based_classify(keystroke_timings)
    
    def _rule_based_classify(self, keystroke_timings: List[Dict]) -> Dict:
        """Simple rule-based classification when ML model is unavailable"""
        if not keystroke_timings or len(keystroke_timings) < 5:
            return {
                'classification': 'unknown',
                'confidence': 0.0,
                'human_probability': 0.5,
                'bot_probability': 0.5,
                'reason': 'insufficient_data'
            }
        
        intervals = [kt['interval_ms'] for kt in keystroke_timings 
                     if kt.get('interval_ms') is not None]
        
        if len(intervals) < 5:
            return {
                'classification': 'unknown',
                'confidence': 0.0,
                'human_probability': 0.5,
                'bot_probability': 0.5,
                'reason': 'insufficient_intervals'
            }
        
        intervals = np.array(intervals)
        
        # Bot indicators
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        fast_ratio = np.sum(intervals < 50) / len(intervals)
        
        # Scoring
        bot_score = 0
        
        # Very fast average typing (<50ms) suggests bot
        if mean_interval < 50:
            bot_score += 2
        elif mean_interval < 80:
            bot_score += 1
        
        # Very consistent timing suggests bot
        if std_interval < 10:
            bot_score += 3
        elif std_interval < 30:
            bot_score += 1
        
        # High ratio of very fast keystrokes suggests bot
        if fast_ratio > 0.8:
            bot_score += 2
        elif fast_ratio > 0.5:
            bot_score += 1
        
        # Determine classification
        if bot_score >= 4:
            classification = 'bot'
            confidence = min(0.5 + bot_score * 0.1, 0.9)
        elif bot_score <= 1:
            classification = 'human'
            confidence = min(0.5 + (5 - bot_score) * 0.1, 0.9)
        else:
            classification = 'uncertain'
            confidence = 0.5
        
        return {
            'classification': classification,
            'confidence': confidence,
            'human_probability': 1 - (bot_score / 7) if classification != 'uncertain' else 0.5,
            'bot_probability': bot_score / 7 if classification != 'uncertain' else 0.5,
            'method': 'rule_based',
            'bot_score': bot_score,
            'indicators': {
                'mean_interval_ms': round(mean_interval, 2),
                'std_interval_ms': round(std_interval, 2),
                'fast_keystroke_ratio': round(fast_ratio, 2)
            }
        }
    
    def _get_top_indicators(self, features: Dict[str, float], 
                            classification: str) -> List[Dict]:
        """Get top indicators that led to the classification"""
        indicators = []
        
        if classification == 'bot':
            # Bot indicators
            if features.get('std_interval', 100) < 20:
                indicators.append({
                    'feature': 'std_interval',
                    'value': round(features['std_interval'], 2),
                    'indicator': 'Very consistent timing (bot-like)'
                })
            
            if features.get('fast_keystrokes_ratio', 0) > 0.7:
                indicators.append({
                    'feature': 'fast_keystrokes_ratio',
                    'value': round(features['fast_keystrokes_ratio'], 2),
                    'indicator': 'High ratio of very fast keystrokes'
                })
            
            if features.get('mean_interval', 200) < 60:
                indicators.append({
                    'feature': 'mean_interval',
                    'value': round(features['mean_interval'], 2),
                    'indicator': 'Very fast average typing speed'
                })
        
        else:  # human
            # Human indicators
            if features.get('std_interval', 0) > 50:
                indicators.append({
                    'feature': 'std_interval',
                    'value': round(features['std_interval'], 2),
                    'indicator': 'Variable timing (human-like)'
                })
            
            if features.get('slow_keystrokes_ratio', 0) > 0.1:
                indicators.append({
                    'feature': 'slow_keystrokes_ratio',
                    'value': round(features['slow_keystrokes_ratio'], 2),
                    'indicator': 'Presence of thinking pauses'
                })
            
            if features.get('burst_count', 0) > 3:
                indicators.append({
                    'feature': 'burst_count',
                    'value': features['burst_count'],
                    'indicator': 'Multiple typing bursts detected'
                })
        
        return indicators[:3]
    
    def _save_model(self):
        """Save model to disk"""
        try:
            os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)
            
            with open(self.MODEL_PATH, 'wb') as f:
                pickle.dump(self.model, f)
            
            with open(self.SCALER_PATH, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logger.info("Model saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def get_feature_importance(self) -> List[Tuple[str, float]]:
        """Get feature importance from the trained model"""
        if not self.is_trained:
            return []
        
        importance = list(zip(self.FEATURE_NAMES, self.model.feature_importances_))
        return sorted(importance, key=lambda x: x[1], reverse=True)
    
    def retrain_with_feedback(self, labeled_data: List[Dict]) -> Dict:
        """
        Retrain model with user-provided labels
        
        labeled_data: List of dicts with 'features' and 'label' (0=human, 1=bot)
        """
        try:
            X = np.array([d['features'] for d in labeled_data])
            y = np.array([d['label'] for d in labeled_data])
            
            return self.train(X, y)
            
        except Exception as e:
            logger.error(f"Error retraining with feedback: {e}")
            return {'error': str(e)}


# Singleton instance
_classifier_instance = None


def get_classifier() -> HumanBotClassifier:
    """Get singleton classifier instance"""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = HumanBotClassifier()
    return _classifier_instance


if __name__ == '__main__':
    # Train model on startup if needed
    classifier = get_classifier()
    
    if not classifier.is_trained:
        print("Training keystroke classifier...")
        results = classifier.train()
        print(f"Training complete!")
        print(f"Validation accuracy: {results['validation_accuracy']:.4f}")
        print(f"\nTop features:")
        for feature, importance in results['top_features']:
            print(f"  {feature}: {importance:.4f}")
