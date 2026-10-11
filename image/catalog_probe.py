"""Query a Redap catalog with the Rerun 0.38.1 Catalog SDK and report what worked."""
import json, sys, time
import rerun as rr

url = sys.argv[1]
report = {"url": url}
started = time.time()
try:
    client = rr.catalog.CatalogClient(url)
    report["version_info"] = str(client.version_info())[:120]
    report["datasets"] = client.dataset_names()
    dataset = client.get_dataset(name=report["datasets"][0])
    segments = dataset.segment_ids() if hasattr(dataset, "segment_ids") else None
    report["segments"] = segments
    frame = dataset.reader(index="frame")
    report["rows"] = frame.count()
    report["ok"] = True
except Exception as error:  # report the failing step instead of a traceback
    report["ok"] = False
    report["error"] = f"{type(error).__name__}: {str(error)[:300]}"
report["seconds"] = round(time.time() - started, 2)
print(json.dumps(report, default=str))
