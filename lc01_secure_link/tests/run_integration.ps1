param(
    [Alias('Binary', 'Executable')]
    [string]$Exe = (Join-Path $PSScriptRoot '..\build\test_endpoint.exe'),
    [string]$LogDir = (Join-Path $PSScriptRoot 'integration-logs'),
    [ValidateRange(15, 300)][int]$TimeoutSeconds = 90,
    [ValidateRange(0, 65529)][int]$BasePort = 0
)

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$LogDir = [IO.Path]::GetFullPath($LogDir)
[void][IO.Directory]::CreateDirectory($LogDir)
$faults = @('none', 'signature', 'finish', 'confirm', 'record', 'ct', 'mode')
$failures = 0

for ($case = 0; $case -lt $faults.Count; $case++) {
    $fault = $faults[$case]
    $jobs = @()
    try {
        if ($BasePort -eq 0) {
            $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            try {
                $probe.Start()
                $port = $probe.LocalEndpoint.Port
            } finally { $probe.Stop() }
        } else { $port = $BasePort + $case }
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        for ($role = 0; $role -lt 2; $role++) {
            $stdout = Join-Path $LogDir "$fault-role$role.stdout.log"
            $stderr = Join-Path $LogDir "$fault-role$role.stderr.log"
            $start = New-Object System.Diagnostics.ProcessStartInfo
            $start.FileName = $Exe
            $start.Arguments = "--test-endpoint $role $port $fault"
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $start
            if (-not $process.Start()) { throw "role $role failed to start" }
            $jobs += [pscustomobject]@{
                Process = $process
                StdoutTask = $process.StandardOutput.ReadToEndAsync()
                StderrTask = $process.StandardError.ReadToEndAsync()
                Stdout = $stdout
                Stderr = $stderr
            }
        }
        while (@($jobs | Where-Object { -not $_.Process.HasExited }).Count -gt 0) {
            if ([DateTime]::UtcNow -ge $deadline) { throw "bounded wait expired ($TimeoutSeconds seconds)" }
            Start-Sleep -Milliseconds 100
        }
        $outputs = @()
        for ($role = 0; $role -lt 2; $role++) {
            $job = $jobs[$role]
            if (-not $job.Process.WaitForExit(2000)) { throw "role $role did not finish" }
            $job.Process.WaitForExit()
            $job.Process.Refresh()
            if ($job.Process.ExitCode -ne 0) { throw "role $role exit=$($job.Process.ExitCode)" }
            $outText = $job.StdoutTask.Result
            $errText = $job.StderrTask.Result
            [IO.File]::WriteAllText($job.Stdout, $outText)
            [IO.File]::WriteAllText($job.Stderr, $errText)
            $outputs += $outText
        }
        if ($fault -eq 'none') {
            $fingerprints = @()
            $digests = @()
            for ($role = 0; $role -lt 2; $role++) {
                $output = $outputs[$role]
                if ($output -notmatch "(?m)^PASS role=$role fault=none\r?$") { throw "role $role missing normal PASS" }
                foreach ($round in @(1, 2)) {
                    $match = [regex]::Match($output, "(?m)^HANDSHAKE_OK role=$role round=$round fingerprint=([0-9a-f]{64})\r?$")
                    if (-not $match.Success) { throw "role $role round $round missing fingerprint" }
                    $fingerprints += $match.Groups[1].Value
                    if ($output -notmatch "(?m)^TEXT_OK role=$role round=$round bidirectional=1 ack=1\r?$") { throw "role $role round $round missing text/ACK proof" }
                }
                if ($fingerprints[2*$role] -eq $fingerprints[2*$role+1]) { throw "role $role fingerprint did not change" }
                foreach ($direction in @('0-to-1', '1-to-0')) {
                    $match = [regex]::Match($output, "(?m)^FILE_OK role=$role direction=$direction bytes=12425 sha256=([0-9a-f]{64})\r?$")
                    if (-not $match.Success) { throw "role $role missing multi-block file proof ($direction)" }
                    $digests += $match.Groups[1].Value
                }
            }
            if ($fingerprints[0] -ne $fingerprints[2] -or $fingerprints[1] -ne $fingerprints[3]) { throw 'endpoints disagree on fingerprints' }
            if (@($digests | Select-Object -Unique).Count -ne 1) { throw 'endpoints disagree on deterministic file SHA-256' }
        } else {
            $stage = if ($fault -eq 'confirm') { 'confirm' } elseif ($fault -eq 'record') { 'record' } else { 'handshake' }
            for ($role = 0; $role -lt 2; $role++) {
                if ($outputs[$role] -notmatch "(?m)^EXPECTED_REJECTION role=$role fault=$fault stage=$stage evidence=(local-validation|peer-validated)\r?$") { throw "role $role missing expected-stage rejection" }
                if ($outputs[$role] -notmatch "(?m)^PASS role=$role fault=$fault\r?$") { throw "role $role missing negative PASS" }
            }
            if ($outputs[1] -notmatch "(?m)^INJECTED role=1 fault=$fault\r?$") { throw 'sender did not inject fault' }
        }
        Write-Output "PASS case=$fault role0_exit=0 role1_exit=0 port=$port"
    } catch {
        $failures++
        Write-Output "FAIL case=$fault reason=$($_.Exception.Message) logs=$LogDir"
    } finally {
        foreach ($job in $jobs) {
            if (-not $job.Process.HasExited) {
                Stop-Process -Id $job.Process.Id -Force -ErrorAction SilentlyContinue
                [void]$job.Process.WaitForExit(3000)
            }
            $job.Process.Dispose()
        }
    }
}
if ($failures -gt 0) { Write-Output "FAIL integration cases_failed=$failures"; exit 1 }
Write-Output 'PASS integration normal=1 negative=6 endpoints=independent-processes'
exit 0
