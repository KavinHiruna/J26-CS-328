"""
run_all.py - ONE command that reproduces every number the presentation uses, then runs the tests.

    python -m backend.component3_soc.run_all        (from the folder that contains backend/, i.e. dev/)

Order: batch pipeline -> calibration -> AHP survey -> survey 2 values -> frequency window evidence -> sensitivity
-> evidence check (config.py = evidence files) -> expert agreement -> parameter register -> unit tests.  Reports are written to docs/results/ (small, committed);
the big alert files go to outputs/ (not committed). Both are inside backend/component3_soc/.
"""
import subprocess
import sys
import time

from . import calibrate, pipeline
from .analysis import ahp_survey, evidence_check, expert_validation, parameter_register, sensitivity, survey2_values, window_evidence
from .config import HERE


def batch_pipeline():
    raw, queue = pipeline.run()
    print(pipeline.summary(raw, queue))
    return {"ok": len(queue) == 26699}


def run_tests():
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(HERE / "test"), "-p", "test_*.py"],
                            cwd=HERE.parents[1])
    return {"ok": result.returncode == 0}


STEPS = [("1. batch pipeline", batch_pipeline), ("2. confidence calibration", calibrate.main),
         ("3. AHP survey -> weights", ahp_survey.main), ("4. survey 2 -> severity and asset values", survey2_values.main),
         ("5. config.py numbers match the evidence files", evidence_check.main),
         ("6. frequency window evidence", window_evidence.main), ("7. sensitivity checks", sensitivity.main),
         ("8. expert agreement", expert_validation.evaluate), ("9. parameter register", parameter_register.main),
         ("10. unit tests", run_tests)]


def main():
    status = []
    for name, step in STEPS:
        print("\n" + "=" * 78 + f"\n{name}\n" + "=" * 78)
        start = time.time()
        try:
            result = step()
            ok = True if result is None else bool(result.get("ok", True))
        except SystemExit as error:
            ok = False
            print("stopped:", error)
        except Exception as error:                      # show the problem, keep going with the other steps
            ok = False
            print(f"ERROR: {type(error).__name__}: {error}")
        status.append((name, ok, time.time() - start))
    print("\n" + "=" * 78 + "\nSUMMARY\n" + "=" * 78)
    for name, ok, seconds in status:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}  ({seconds:.0f} s)")
    print("\nAll steps passed." if all(ok for _, ok, _ in status) else "\nSome steps failed: read the messages above.")
    return all(ok for _, ok, _ in status)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
