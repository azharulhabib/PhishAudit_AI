"""Picklable stand-in for the served forest. It is never fitted; tests only need a loadable object."""
import numpy as np


class StubForest:
    def __init__(self, probability=0.5, classes=(0, 1), n_features=37):
        self.probability = probability
        self.classes_ = np.array(classes)
        self.n_features_in_ = n_features
        self.n_jobs = 2

    def predict_proba(self, matrix):
        return np.array([[1.0 - self.probability, self.probability]] * len(matrix))
