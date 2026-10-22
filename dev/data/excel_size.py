"""
Extract roughly TARGET_MB of data from a very large .xlsx file into a new, smaller .xlsx file.

Why this approach:
- pandas.read_excel / normal openpyxl load the whole 400 MB workbook into RAM (often 5-10 GB) and are slow.
- openpyxl in read_only mode streams rows one at a time, and write_only mode streams them out.
- .xlsx is zip-compressed, so you can't know the output size until it's saved. The script
  writes a small calibration sample first, measures bytes-per-row, then writes the final file
  with the estimated row count, and corrects once if it misses the target by more than 15%.

Usage:
    pip install openpyxl
    python excel_sample.py big_file.xlsx small_file.xlsx --mb 10
    python excel_sample.py big_file.xlsx small_file.csv  --mb 10      # CSV output (exact size, much faster)
    python excel_sample.py big_file.xlsx out.xlsx --mb 10 --sheet "Sheet1"
    python excel_sample.py big_file.csv  small_file.csv  --mb 15      # CSV input (streams, keeps header)
"""

import argparse
import csv
import itertools
import os
import tempfile

from openpyxl import Workbook, load_workbook

CALIBRATION_ROWS = 20_000


def open_rows(path, sheet_name=None):
    """Return (workbook, row iterator) streaming values from the chosen sheet."""
    wb = load_workbook(path, read_only=True, data_only=True)
    ws = wb[sheet_name] if sheet_name else wb.worksheets[0]
    return wb, ws.iter_rows(values_only=True)


def write_xlsx(src, dst, n_rows, sheet_name=None):
    """Copy the first n_rows rows (header included) from src to dst. Returns rows written."""
    wb_in, rows = open_rows(src, sheet_name)
    wb_out = Workbook(write_only=True)
    ws_out = wb_out.create_sheet(title="data")
    count = 0
    for row in itertools.islice(rows, n_rows):
        ws_out.append(row)
        count += 1
    wb_out.save(dst)
    wb_in.close()
    return count


def extract_xlsx(src, dst, target_bytes, sheet_name=None):
    # 1) Calibrate: write a sample and measure compressed bytes per row
    fd, tmp = tempfile.mkstemp(suffix=".xlsx")
    os.close(fd)
    try:
        sample_rows = write_xlsx(src, tmp, CALIBRATION_ROWS, sheet_name)
        sample_size = os.path.getsize(tmp)
    finally:
        os.remove(tmp)

    if sample_size >= target_bytes or sample_rows < CALIBRATION_ROWS:
        # Sample already big enough, or the whole sheet is smaller than the sample
        n = sample_rows if sample_size < target_bytes else int(sample_rows * target_bytes / sample_size)
        written = write_xlsx(src, dst, max(n, 1), sheet_name)
        return written

    bytes_per_row = sample_size / sample_rows
    n_rows = int(target_bytes / bytes_per_row)
    print(f"Calibration: {bytes_per_row:.1f} bytes/row -> writing ~{n_rows:,} rows")

    # 2) Write the real file
    written = write_xlsx(src, dst, n_rows, sheet_name)
    size = os.path.getsize(dst)

    # 3) One correction pass if we're more than 15% off (compression ratio varies with data)
    if written == n_rows and abs(size - target_bytes) / target_bytes > 0.15:
        n_rows = int(written * target_bytes / size)
        print(f"Got {size / 1e6:.1f} MB, adjusting to {n_rows:,} rows")
        written = write_xlsx(src, dst, n_rows, sheet_name)

    return written


def extract_csv(src, dst, target_bytes, sheet_name=None):
    """CSV isn't compressed, so we can stop at exactly the target size."""
    wb_in, rows = open_rows(src, sheet_name)
    written = 0
    with open(dst, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(["" if v is None else v for v in row])
            written += 1
            if written % 1000 == 0 and f.tell() >= target_bytes:
                break
    wb_in.close()
    return written


def extract_csv_from_csv(src, dst, target_bytes):
    """CSV -> CSV: copy the header and first rows until the output reaches the target size."""
    written = 0
    with open(src, newline="", encoding="utf-8", errors="replace") as f_in, \
            open(dst, "w", newline="", encoding="utf-8") as f_out:
        reader, writer = csv.reader(f_in), csv.writer(f_out)
        for row in reader:
            writer.writerow(row)
            written += 1
            if written % 1000 == 0 and f_out.tell() >= target_bytes:
                break
    return written


def main():
    p = argparse.ArgumentParser(description="Extract ~N MB of rows from a huge Excel file.")
    p.add_argument("src", help="Big input .xlsx file")
    p.add_argument("dst", help="Output file (.xlsx or .csv)")
    p.add_argument("--mb", type=float, default=10, help="Target output size in MB (default 10)")
    p.add_argument("--sheet", default=None, help="Sheet name (default: first sheet)")
    args = p.parse_args()

    target = int(args.mb * 1024 * 1024)
    if args.src.lower().endswith(".csv"):
        rows = extract_csv_from_csv(args.src, args.dst, target)
    elif args.dst.lower().endswith(".csv"):
        rows = extract_csv(args.src, args.dst, target, args.sheet)
    else:
        rows = extract_xlsx(args.src, args.dst, target, args.sheet)

    size_mb = os.path.getsize(args.dst) / (1024 * 1024)
    print(f"Done: {rows:,} rows written to {args.dst} ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()
