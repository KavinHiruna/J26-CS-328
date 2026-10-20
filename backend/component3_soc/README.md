# Component 3

Owner: <name>

## Inputs
## Outputs (see docs/interfaces.md)
## How to run
## How to test

## Contents to move here from the standalone project (D:\Reserch\SOC_Component3)
- `src/*.py`  -> `backend/component3_soc/` (same file names)
- `data/`, `docs/`, `outputs/`, `models/` -> `backend/component3_soc/` (same sub-folders)
- `dashboard/app.py` + `dashboard/soc_logic.py` -> `frontend/pages/3_SOC_Prioritisation.py`
  (logic stays in `backend/component3_soc/soc_logic.py`; the page only displays it)
Paths inside the code use `ROOT = Path(__file__).resolve().parent`, so they keep working after the move.
