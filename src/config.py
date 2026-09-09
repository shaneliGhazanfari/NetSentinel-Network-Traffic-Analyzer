from pathlib import Path

project_root = Path(__file__).resolve().parent.parent

dataset_dir = project_root / "datasets"

output_dir = project_root / "output"
output_dir.mkdir(exist_ok=True)

dataset_file = [
    dataset_dir / "UNSW-NB15_1.csv",
    dataset_dir / "UNSW-NB15_2.csv",
    dataset_dir / "UNSW-NB15_3.csv",
    dataset_dir / "UNSW-NB15_4.csv",
]

features_file = dataset_dir / "UNSW-NB15_features.csv"
events_file = dataset_dir / "UNSW-NB15_LIST_EVENTS.csv"