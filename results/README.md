# Baseline results

`results/runs/` is ignored and is the default destination for local benchmark runs.
Checked examples live in `results/examples/` and use the exact schema emitted by
`mtc.experiment.recorder.MetricsRecorder`.

Run the quick baseline from the repository root:

```powershell
.\scripts\run_baseline.ps1
```

Large configurations require both an explicit config and `-AllowLarge`.
