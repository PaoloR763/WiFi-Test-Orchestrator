$ErrorActionPreference = 'Stop'
python "$PSScriptRoot/generate_env.py" @args
if ($LASTEXITCODE -ne 0) { throw 'Environment generation failed' }
