import sys
from pathlib import Path

# The Lambda imports its modules flat (as they sit in the deployment zip).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lambda" / "risk_engine"))
