import sys
from pathlib import Path

# Each Lambda imports its modules flat (as they sit in its deployment zip).
ROOT = Path(__file__).resolve().parents[1]
for function_dir in ("risk_engine", "report"):
    sys.path.insert(0, str(ROOT / "lambda" / function_dir))
