#!/usr/bin/env python3
"""
AI/ML Training Module for XSS Payload Generation
"""

import json
import numpy as np
import tensorflow as tf
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
from typing import List, Dict, Tuple

from utils.logger import get_logger

class XSSTrainer:
    """AI trainer for XSS payload generation and response analysis"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.vectorizer = TfidfVectorizer(max_features=5000)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.neural_model = None
        
    def train_from_file(self, training_file: str):
        """Train models from training data file"""
        self.logger.info(f"Training models from: {training_file}")
        
        # Load training data
        with open(training_file, 'r') as f:
            training_data = json.load(f)
        
        # Prepare data for training
        X, y = self._prepare_training_data(training_data)
        
        # Train traditional ML model
        self._train_traditional_model(X, y)
        
        # Train neural network model
        self._train_neural_model(X, y)
        
        # Save models
        self._save_models()
        
        self.logger.info("Training completed successfully")
    
    def _prepare_training_data(self, training_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        features = []
        labels = []
        
        for item in training_data:
            # Extract features from response
            response_features = self._extract_response_features(item['response'])
            features.append(response_features)
            
            # Extract label (successful XSS or not)
            labels.append(1 if item['success'] else 0)
        
        # Vectorize features
        feature_text = [' '.join(map(str, f)) for f in features]
        X = self.vectorizer.fit_transform(feature_text)
        y = np.array(labels)
        
        return X, y
    
    def _extract_response_features(self, response: Dict) -> List[str]:
        """Extract features from HTTP response"""
        features = []
        
        # Response code
        features.append(f"status_{response.get('status_code', 200)}")
        
        # Content type
        content_type = response.get('headers', {}).get('content-type', '')
        features.append(f"content_type_{content_type.split(';')[0]}")
        
        # Response body analysis
        body = response.get('body', '')
        
        # Check for XSS indicators in response
        xss_indicators = [
            'alert', 'confirm', 'prompt', 'onerror', 'onload',
            'script', 'javascript:', 'eval', 'document.cookie'
        ]
        
        for indicator in xss_indicators:
            if indicator in body.lower():
                features.append(f"contains_{indicator}")
        
        # Check for security headers
        headers = response.get('headers', {})
        security_headers = [
            'x-xss-protection', 'content-security-policy',
            'x-frame-options', 'x-content-type-options'
        ]
        
        for header in security_headers:
            if header in headers:
                features.append(f"has_{header}")
        
        # Response length
        features.append(f"length_{len(body)}")
        
        return features
    
    def _train_traditional_model(self, X: np.ndarray, y: np.ndarray):
        """Train traditional ML classifier"""
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.classifier.fit(X_train, y_train)
        
        # Evaluate model
        train_score = self.classifier.score(X_train, y_train)
        test_score = self.classifier.score(X_test, y_test)
        
        self.logger.info(f"Traditional model - Train score: {train_score:.3f}, Test score: {test_score:.3f}")
    
    def _train_neural_model(self, X: np.ndarray, y: np.ndarray):
        """Train neural network model"""
        X_train, X_test, y_train, y_test = train_test_split(
            X.toarray(), y, test_size=0.2, random_state=42
        )
        
        # Build neural network
        self.neural_model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.neural_model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        # Train model
        history = self.neural_model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=50,
            batch_size=32,
            verbose=1
        )
        
        # Evaluate model
        test_loss, test_accuracy = self.neural_model.evaluate(X_test, y_test, verbose=0)
        self.logger.info(f"Neural model - Test accuracy: {test_accuracy:.3f}")
    
    def _save_models(self):
        """Save trained models"""
        # Save traditional model
        with open('ai/traditional_model.pkl', 'wb') as f:
            pickle.dump(self.classifier, f)
        
        # Save vectorizer
        with open('ai/vectorizer.pkl', 'wb') as f:
            pickle.dump(self.vectorizer, f)
        
        # Save neural model
        if self.neural_model:
            self.neural_model.save('ai/neural_model.h5')
        
        self.logger.info("Models saved successfully")
