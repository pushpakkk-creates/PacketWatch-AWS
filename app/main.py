from pathlib import Path
import io
import json
import random

import joblib
import numpy as np
import pandas as pd
from faker import Faker
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score,
)
from sklearn.pipeline import Pipeline


# --------------------------------------------------
# PATHS AND CONFIGURATION
# --------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"
DATA_RAW_DIR = ROOT / "data" / "raw"

MODEL_PATH = MODEL_DIR / "packetwatch_model.joblib"
REPORT_PATH = REPORT_DIR / "latest_report.json"

MAX_ROWS = 100_000
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
RANDOM_STATE = 42

IDENTIFIERS = {
    "label", "target", "source_file", "flow id",
    "source ip", "destination ip", "src ip", "dst ip",
    "timestamp", "simillarhttp", "similarhttp",
}

app = FastAPI(title="PacketWatch API", version="1.1.0")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# --------------------------------------------------
# DATA PREPARATION
# --------------------------------------------------

def normalized(df):
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    return df


def label_column(df):
    return next(
        (c for c in df.columns if c.strip().lower() == "label"),
        None,
    )


def features(df):
    """Keep usable numeric features and remove identifiers."""
    result = df.copy()
    selected = []

    for col in result.columns:
        if col.strip().lower() in IDENTIFIERS:
            continue

        values = pd.to_numeric(result[col], errors="coerce")
        values = values.replace([np.inf, -np.inf], np.nan)

        if values.notna().any():
            result[col] = values
            selected.append(col)

    return result[selected].dropna(axis=1, how="all")


def make_pipeline():
    """Median imputation followed by a Random Forest classifier."""
    return Pipeline([
        (
            "imputer",
            SimpleImputer(
                strategy="median",
                keep_empty_features=True,
            ),
        ),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=200,
                max_depth=12,
                min_samples_leaf=3,
                min_samples_split=6,
                max_features="sqrt",
                class_weight="balanced",
                n_jobs=-1,
                random_state=RANDOM_STATE,
            ),
        ),
    ])


async def read_csv_upload(file):
    """Validate upload size, extension and CSV readability."""
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Please upload a CSV file.")

    content = await file.read()

    if not content:
        raise HTTPException(400, "The uploaded CSV is empty.")

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413,
            "CSV exceeds the 25 MB upload limit.",
        )

    try:
        df = pd.read_csv(
            io.BytesIO(content),
            nrows=MAX_ROWS,
            low_memory=False,
        )
    except Exception as exc:
        raise HTTPException(400, f"Could not read CSV: {exc}")

    df = normalized(df)

    if df.empty:
        raise HTTPException(400, "The CSV contains no usable rows.")

    return df


# --------------------------------------------------
# SYNTHETIC DATA GENERATOR
# --------------------------------------------------

@app.post("/api/generate-dataset")
def generate_dataset(
    rows: int = Query(250, ge=100, le=500),
    attack_percent: int = Query(25, ge=5, le=50),
):
    """
    Generate educational synthetic network-flow records.
    This is simulated data, not captured network traffic.
    """
    rng = random.Random()
    fake = Faker()
    fake.seed_instance(rng.randrange(1, 2**31 - 1))

    attack_count = round(rows * attack_percent / 100)
    attack_indexes = set(rng.sample(range(rows), attack_count))

    # Both classes can use these ports. Port alone should not
    # reveal the label deterministically.
    common_ports = [
        22, 23, 25, 53, 80, 110, 123, 143, 443,
        445, 587, 993, 1433, 3306, 3389, 4444, 8080,
    ]

    start = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=2)
    records = []

    for i in range(rows):
        is_attack = i in attack_indexes

        # Overlapping distributions are intentional.
        # The values are illustrative, not real traffic measurements.
        if is_attack:
            duration = int(rng.lognormvariate(9.7, 1.05))
            fwd = max(1, int(rng.gauss(75, 55)))
            bwd = max(1, int(rng.gauss(25, 20)))
            byte_rate = max(10.0, rng.lognormvariate(8.5, 1.25))
            packet_rate = max(0.5, rng.lognormvariate(3.2, 1.0))
            packet_mean = min(1500.0, max(40.0, rng.gauss(600, 300)))
            syn_count = max(0, int(rng.gauss(5, 5)))
            active_mean = max(0.0, rng.gauss(180000, 190000))
            idle_mean = max(0.0, rng.gauss(400000, 350000))
            label = rng.choice(["ATTACK", "DoS", "PortScan", "BruteForce"])
        else:
            duration = int(rng.lognormvariate(9.3, 1.0))
            fwd = max(1, int(rng.gauss(40, 35)))
            bwd = max(1, int(rng.gauss(22, 18)))
            byte_rate = max(10.0, rng.lognormvariate(8.0, 1.2))
            packet_rate = max(0.5, rng.lognormvariate(3.0, 0.9))
            packet_mean = min(1500.0, max(40.0, rng.gauss(500, 280)))
            syn_count = max(0, int(rng.gauss(3, 3)))
            active_mean = max(0.0, rng.gauss(140000, 160000))
            idle_mean = max(0.0, rng.gauss(350000, 320000))
            label = "BENIGN"

        # Occasional noise creates more variation between records.
        if rng.random() < 0.12:
            byte_rate *= rng.uniform(0.3, 2.5)
            packet_rate *= rng.uniform(0.5, 2.0)
            fwd = max(1, int(fwd * rng.uniform(0.5, 1.8)))

        timestamp = (
            start + pd.Timedelta(seconds=i * rng.randint(1, 8))
        ).isoformat()

        records.append({
            "Flow ID": f"SYN-{i + 1:05d}",
            "Source IP": fake.ipv4_private(),
            "Destination IP": fake.ipv4_private(),
            "Timestamp": timestamp,
            "Flow Duration": duration,
            "Tot Fwd Pkts": fwd,
            "Tot Bwd Pkts": bwd,
            "Flow Bytes/s": round(byte_rate, 3),
            "Flow Packets/s": round(packet_rate, 3),
            "Packet Length Mean": round(packet_mean, 3),
            "SYN Flag Count": syn_count,
            "Destination Port": rng.choice(common_ports),
            "Active Mean": round(active_mean, 3),
            "Idle Mean": round(idle_mean, 3),
            "Label": label,
        })

    df = pd.DataFrame(records)

    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    csv_text = df.to_csv(index=False)
    output_path = DATA_RAW_DIR / "generated_traffic.csv"
    output_path.write_text(csv_text, encoding="utf-8")

    return {
        "filename": output_path.name,
        "rows": len(df),
        "columns": len(df.columns),
        "column_names": list(df.columns),
        "has_label": True,
        "label_counts": {
            str(k): int(v)
            for k, v in df["Label"].value_counts().items()
        },
        "preview": df.head(8).replace({np.nan: None}).to_dict(
            orient="records"
        ),
        "csv": csv_text,
        "synthetic": True,
        "note": (
            "Synthetic educational data only. "
            "Metrics on this data do not establish real-world accuracy."
        ),
    }


# --------------------------------------------------
# HOME AND STATUS
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/api/status")
def status():
    report = {}

    if REPORT_PATH.exists():
        try:
            report = json.loads(
                REPORT_PATH.read_text(encoding="utf-8")
            )
        except Exception:
            report = {}

    return {
        "model_ready": MODEL_PATH.exists(),
        "last_training": report,
        "app": "PacketWatch",
        "max_rows": MAX_ROWS,
    }


# --------------------------------------------------
# DATASET INSPECTION
# --------------------------------------------------

@app.post("/api/inspect")
async def inspect(file: UploadFile = File(...)):
    df = await read_csv_upload(file)
    col = label_column(df)

    counts = {}
    if col:
        labels = df[col].astype("string").str.strip().fillna("UNKNOWN")
        counts = {
            str(k): int(v)
            for k, v in labels.value_counts().head(20).items()
        }

    return {
        "filename": file.filename,
        "rows": len(df),
        "columns": len(df.columns),
        "column_names": list(df.columns[:80]),
        "has_label": bool(col),
        "label_counts": counts,
        "preview": df.head(8).replace({np.nan: None}).to_dict(
            orient="records"
        ),
    }


# --------------------------------------------------
# MODEL TRAINING AND EVALUATION
# --------------------------------------------------

@app.post("/api/train")
async def train(file: UploadFile = File(...)):
    df = await read_csv_upload(file)

    label_col = label_column(df)
    if not label_col:
        raise HTTPException(
            400,
            "Training CSV must contain a column named 'Label'.",
        )

    labels = df[label_col].astype("string").str.strip().fillna("UNKNOWN")
    valid = labels.ne("UNKNOWN") & labels.ne("")

    df = df.loc[valid].copy()
    labels = labels.loc[valid]

    # Binary classification: BENIGN = 0; every other label = 1.
    y = (labels.str.upper() != "BENIGN").astype("int8")
    x = features(df.drop(columns=[label_col]))

    if x.empty:
        raise HTTPException(
            400,
            "No usable numeric traffic features were found.",
        )

    usable = ~x.isna().all(axis=1)
    x, y, labels = x.loc[usable], y.loc[usable], labels.loc[usable]

    class_counts = y.value_counts()

    if len(x) < 30 or y.nunique() < 2:
        raise HTTPException(
            400,
            "Need at least 30 usable rows and both BENIGN and ATTACK labels.",
        )

    if class_counts.min() < 2:
        raise HTTPException(
            400,
            "Each binary class needs at least two records.",
        )

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = make_pipeline()
    model.fit(x_train, y_train)

    # Compare performance on training and held-out test rows.
    train_pred = model.predict(x_train)
    test_pred = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]

    matrix = confusion_matrix(y_test, test_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    try:
        auc = float(roc_auc_score(y_test, probabilities))
    except ValueError:
        auc = None

    # Stratified cross-validation on the available dataset.
    # This remains an internal estimate, not independent real-world testing.
    min_class = int(class_counts.min())
    cv_f1_mean = None
    cv_f1_std = None
    cv_splits = min(5, min_class)

    if cv_splits >= 2:
        cv = StratifiedKFold(
            n_splits=cv_splits,
            shuffle=True,
            random_state=RANDOM_STATE,
        )
        cv_scores = cross_val_score(
            make_pipeline(),
            x,
            y,
            cv=cv,
            scoring="f1",
            n_jobs=1,
        )
        cv_f1_mean = float(cv_scores.mean())
        cv_f1_std = float(cv_scores.std())

    classifier = model.named_steps["classifier"]
    importances = sorted(
        [
            {
                "feature": name,
                "importance": float(value),
            }
            for name, value in zip(x.columns, classifier.feature_importances_)
        ],
        key=lambda item: item["importance"],
        reverse=True,
    )

    metrics = {
        "rows_used": int(len(x)),
        "features_used": int(x.shape[1]),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "train_accuracy": float(accuracy_score(y_train, train_pred)),
        "accuracy": float(accuracy_score(y_test, test_pred)),
        "balanced_accuracy": float(
            balanced_accuracy_score(y_test, test_pred)
        ),
        "precision": float(
            precision_score(y_test, test_pred, zero_division=0)
        ),
        "recall": float(
            recall_score(y_test, test_pred, zero_division=0)
        ),
        "f1": float(f1_score(y_test, test_pred, zero_division=0)),
        "specificity": float(specificity),
        "roc_auc": auc,
        "matthews_corrcoef": float(
            matthews_corrcoef(y_test, test_pred)
        ),
        "cv_f1_mean": cv_f1_mean,
        "cv_f1_std": cv_f1_std,
        "cv_splits": cv_splits if cv_splits >= 2 else 0,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_test,
            test_pred,
            labels=[0, 1],
            target_names=["BENIGN", "ATTACK"],
            output_dict=True,
            zero_division=0,
        ),
        "feature_importance": importances,
        "label_counts": {
            str(k): int(v)
            for k, v in labels.value_counts().items()
        },
        "target_definition": "BENIGN=0; any non-BENIGN label=1",
        "algorithm": "Random Forest Classifier",
        "evaluation_note": (
            "Test metrics use a stratified holdout from the uploaded dataset. "
            "Cross-validation is an additional internal estimate. "
            "Synthetic data metrics do not establish real-world performance."
        ),
        "trained_at": pd.Timestamp.now(tz="UTC").isoformat(),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "features": list(x.columns),
            "algorithm": "Random Forest Classifier",
        },
        MODEL_PATH,
    )

    REPORT_PATH.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    return metrics


# --------------------------------------------------
# TRAFFIC ANALYSIS
# --------------------------------------------------

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not MODEL_PATH.exists():
        raise HTTPException(400, "Train a model first.")

    raw = await read_csv_upload(file)

    saved = joblib.load(MODEL_PATH)
    model = saved["model"]
    feature_names = saved["features"]

    label_col = label_column(raw)
    x = features(raw.drop(columns=[label_col]) if label_col else raw)
    x = x.reindex(columns=feature_names, fill_value=np.nan)

    predictions = model.predict(x)
    result = raw.copy()

    result["Prediction"] = np.where(
        predictions == 1,
        "ATTACK",
        "BENIGN",
    )

    if hasattr(model, "predict_proba"):
        result["Attack_Probability"] = (
            model.predict_proba(x)[:, 1].round(4)
        )

    counts = result["Prediction"].value_counts().to_dict()

    return {
        "rows": len(result),
        "attack_count": int(counts.get("ATTACK", 0)),
        "benign_count": int(counts.get("BENIGN", 0)),
        "columns": list(result.columns),
        "results": result.head(1000).replace({np.nan: None}).to_dict(
            orient="records"
        ),
        "csv": result.to_csv(index=False),
    }