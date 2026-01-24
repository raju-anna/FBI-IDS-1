import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler


def sanitize_input(X: pd.DataFrame) -> pd.DataFrame:
    """
    Replace infinite values with NaN.
    This must be called before preprocessing pipeline.
    """
    X = X.copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    return X


def build_preprocessing_pipeline() -> Pipeline:
    """
    Deterministic preprocessing pipeline for IDS.
    - Median imputation for missing values
    - Standard scaling for feature normalization

    This pipeline is part of the model and must be frozen.
    """
    pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ]
    )

    return pipeline
