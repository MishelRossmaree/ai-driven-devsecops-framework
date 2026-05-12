import pandas as pd
from pathlib import Path
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer


DATA_DIR = Path("data/processed/commit_risk")
FEATURE_DIR = Path("data/features/commit_risk")

TRAIN_PATH = DATA_DIR / "train.csv"
VALID_PATH = DATA_DIR / "valid.csv"
TEST_PATH = DATA_DIR / "test.csv"

VECTORIZER_PATH = FEATURE_DIR / "tfidf_vectorizer.pkl"

MAX_FEATURES = 5000


def load_dataset(file_path):
    df = pd.read_csv(file_path)

    df["function_code"] = df["function_code"].fillna("")
    df["target"] = df["target"].astype(int)

    return df


def main():
    FEATURE_DIR.mkdir(parents=True, exist_ok=True)

    train_df = load_dataset(TRAIN_PATH)
    valid_df = load_dataset(VALID_PATH)
    test_df = load_dataset(TEST_PATH)

    vectorizer = TfidfVectorizer(
        max_features=MAX_FEATURES,
        token_pattern=r"(?u)\b\w+\b",
        lowercase=False
    )

    X_train = vectorizer.fit_transform(train_df["function_code"])
    X_valid = vectorizer.transform(valid_df["function_code"])
    X_test = vectorizer.transform(test_df["function_code"])

    y_train = train_df["target"]
    y_valid = valid_df["target"]
    y_test = test_df["target"]

    joblib.dump(vectorizer, VECTORIZER_PATH)

    joblib.dump(X_train, FEATURE_DIR / "X_train.pkl")
    joblib.dump(X_valid, FEATURE_DIR / "X_valid.pkl")
    joblib.dump(X_test, FEATURE_DIR / "X_test.pkl")

    joblib.dump(y_train, FEATURE_DIR / "y_train.pkl")
    joblib.dump(y_valid, FEATURE_DIR / "y_valid.pkl")
    joblib.dump(y_test, FEATURE_DIR / "y_test.pkl")

    print("Commit risk TF-IDF features prepared successfully")
    print(f"TF-IDF max features: {MAX_FEATURES}")
    print(f"X_train shape: {X_train.shape}")
    print(f"X_valid shape: {X_valid.shape}")
    print(f"X_test shape: {X_test.shape}")
    print(f"Vectorizer saved to: {VECTORIZER_PATH}")


if __name__ == "__main__":
    main()