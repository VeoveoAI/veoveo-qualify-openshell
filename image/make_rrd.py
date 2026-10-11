"""Write a small Rerun 0.38.1 dataset segment for the Redap catalog probes."""
import sys
import rerun as rr

out = sys.argv[1]
rec = rr.RecordingStream("probe-dataset", recording_id="probe-segment-1")
rec.save(out)
for i in range(2000):
    rec.set_time("frame", sequence=i)
    rec.log("points", rr.Points3D([[i * 0.01, 0.0, 0.0], [0.0, i * 0.01, 0.0]]))
    rec.log("scalar", rr.Scalars(float(i)))
rec.flush()
print(out)
