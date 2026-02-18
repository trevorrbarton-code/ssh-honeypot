#!/usr/bin/env python3
"""
Machine Learning Module for SSH Honeypot
Keystroke dynamics analysis and human/bot classification
"""

from .keystroke_classifier import (
    HumanBotClassifier,
    KeystrokeFeatureExtractor,
    get_classifier
)

__all__ = [
    'HumanBotClassifier',
    'KeystrokeFeatureExtractor',
    'get_classifier'
]
