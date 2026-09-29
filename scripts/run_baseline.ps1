param(
    [string]$Config = "configs/baseline-fast.json",
    [string]$OutputDirectory = "results/runs/baseline",
    [switch]$AllowLarge
)

$arguments = @(
    "-m", "mtc.experiment.runner",
    "--config", $Config,
    "--output-dir", $OutputDirectory
)
if ($AllowLarge) {
    $arguments += "--allow-large"
}
& ".\.venv\Scripts\python.exe" @arguments
exit $LASTEXITCODE
