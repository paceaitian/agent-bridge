# Windows 本机专用会话 ONLY。先完整读 W1-gate-brief.md。
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Python,
      [ValidateSet('desktop','tool-job','rmux','ssh')][string]$Context='desktop',
      [string]$SecondPython='')
$ErrorActionPreference='Stop'
trap { Write-Output 'W1 gate bootstrap failed (details suppressed).'; exit 1 }
$bundle=$PSScriptRoot
$manifest=Get-Content -LiteralPath (Join-Path $bundle 'W1-gate-manifest.json') -Raw | ConvertFrom-Json
foreach($name in @('W1-gate-src.tar','W1-gate-run.py','w1_gate_native.py')) {
  $actual=(Get-FileHash -LiteralPath (Join-Path $bundle $name) -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -ne $manifest.files.$name) { throw 'gate_artifact_hash_mismatch' }
}
$me=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[System.Security.Principal.WindowsPrincipal]::new($me)
if($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'non_elevated_required' }
$base=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$root=Join-Path (Join-Path $base 'Temp') ('ab-w1-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
if(Test-Path -LiteralPath $root) { throw 'private_root_already_exists' }
$security=[System.Security.AccessControl.DirectorySecurity]::new()
$security.SetOwner($me.User)
$security.SetAccessRuleProtection($true,$false)
$inherit=[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$prop=[System.Security.AccessControl.PropagationFlags]::None
$allow=[System.Security.AccessControl.AccessControlType]::Allow
foreach($sid in @($me.User,[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
  $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,$prop,$allow))
}
# .NET API creates with supplied DACL, not public create followed by Set-Acl.
[void][System.IO.FileSystemAclExtensions]::CreateDirectory($security,$root)
$oldTmp=$env:TMP; $oldTemp=$env:TEMP; $oldPythonPath=$env:PYTHONPATH; $oldBytecode=$env:PYTHONDONTWRITEBYTECODE
$status=1
try {
  $env:TEMP=$root; $env:TMP=$root
  $env:PYTHONDONTWRITEBYTECODE='1'
  # Hash checked first; only regular files/directories, no links/traversal.
  & $Python -I -B -c 'import sys,tarfile,pathlib; p=pathlib.Path(sys.argv[2]); t=tarfile.open(sys.argv[1]); assert all(x.isfile() or x.isdir() for x in t.getmembers()); t.extractall(p,filter="data")' (Join-Path $bundle 'W1-gate-src.tar') (Join-Path $root 'source') 2>$null
  if($LASTEXITCODE -ne 0) { throw 'source_extract_failed' }
  Copy-Item -LiteralPath (Join-Path $bundle 'W1-gate-run.py') -Destination (Join-Path $root 'W1-gate-run.py')
  Copy-Item -LiteralPath (Join-Path $bundle 'w1_gate_native.py') -Destination (Join-Path $root 'w1_gate_native.py')
  # Explicit private negative fixtures. No business ACL or junction is modified.
  $wide=Join-Path $root 'wide'
  $broad=[System.Security.AccessControl.DirectorySecurity]::new()
  $broad.SetOwner($me.User);$broad.SetAccessRuleProtection($true,$false)
  foreach($sid in @($me.User,[System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'))) {
    $broad.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,$prop,$allow))
  }
  [void][System.IO.FileSystemAclExtensions]::CreateDirectory($broad,$wide)
  $real=Join-Path $root 'junction-target'
  [void][System.IO.FileSystemAclExtensions]::CreateDirectory($security,$real)
  New-Item -ItemType Junction -Path (Join-Path $root 'junction') -Target $real | Out-Null
  $env:PYTHONPATH=Join-Path $root 'source/src'
  $argsList=@((Join-Path $root 'W1-gate-run.py'),'--root',$root,'--output',$bundle,'--context',$Context,'--source-sha',$manifest.files.'W1-gate-src.tar')
  if($SecondPython) { $argsList+=@('--second-python',$SecondPython) }
  & $Python @argsList
  $status=$LASTEXITCODE
} catch {
  # Do not print exception text/stack containing usernames or native object names.
  Write-Output 'W1 gate stopped: bootstrap_or_runner_failed; inspect only this private fixture locally.'
} finally {
  $env:TMP=$oldTmp; $env:TEMP=$oldTemp; $env:PYTHONPATH=$oldPythonPath; $env:PYTHONDONTWRITEBYTECODE=$oldBytecode
  $residual=$false
  try {
    $resultFile=Join-Path $bundle 'W1-gate-results.json'
    if(Test-Path -LiteralPath $resultFile) {
      $history=Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
      $last=$history.runs[-1]
      if($last.rootName -ne [IO.Path]::GetFileName($root)) { throw 'runner_evidence_not_this_root' }
      $boundary=$last.results | Where-Object { $_.id -eq 'G6-boundary' }
      if(-not $boundary -or $null -eq $boundary.evidence.ownedLive) { throw 'runner_boundary_missing' }
      if($boundary.evidence.ownedLive -gt 0) { throw 'fixture_still_alive_preserve_root' }
    } elseif($status -ne 0) { throw 'runner_evidence_missing_preserve_root' }
    $junction=Join-Path $root 'junction'
    if(Test-Path -LiteralPath $junction) { [System.IO.Directory]::Delete($junction) }
    if(Test-Path -LiteralPath $root) {
      # Exact freshly generated root; never follow links or broaden to Temp.
      # Python lstat exposes st_reparse_tag; no binary analysis/remote call.
      # Cleanup walks only ordinary directories, unlinks ONLY exact AF_UNIX
      # non-directory residues. Any other reparse preserves the entire root.
      $cleanupJson=& $Python -I -B (Join-Path $root 'W1-gate-run.py') --root $root --cleanup-reparse
      if($LASTEXITCODE -ne 0) { throw 'unexpected_reparse_residue' }
      $cleanup=$cleanupJson | ConvertFrom-Json
      if(-not $cleanup.safe -or $cleanup.unknownReparse -ne 0) { throw 'unverified_reparse_residue' }
      Remove-Item -LiteralPath $root -Recurse -Force
    }
  } catch { $residual=$true }
  # Only generated basename, not username/full path; append-only cleanup evidence.
  [pscustomobject]@{context=$Context;rootName=[IO.Path]::GetFileName($root);rootRemaining=$residual;runnerExit=$status} |
    ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $bundle 'W1-gate-cleanup.jsonl') -Encoding utf8
  if($residual) { Write-Output 'W1 private-root cleanup incomplete; see sanitized cleanup manifest.'; $status=1 }
}
exit $status
