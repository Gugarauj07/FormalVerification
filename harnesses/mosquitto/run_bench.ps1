# Benchmark all Mosquitto ESBMC harnesses: records wall-clock time and peak memory.
# Output: bench_results.csv in the harnesses/mosquitto directory.
param(
    [string]$EsbmcPath = ""
)

$ErrorActionPreference = "Continue"
$Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $EsbmcPath) {
    $default = Join-Path $Root "tools\esbmc\bin\esbmc.exe"
    if (Test-Path $default) { $EsbmcPath = $default }
    elseif (Get-Command esbmc -ErrorAction SilentlyContinue) { $EsbmcPath = "esbmc" }
    else { throw "ESBMC not found. Install to tools/esbmc or add to PATH." }
}

Set-Location $Root
$logDir = Join-Path $Root "harnesses\mosquitto"
$csvPath = Join-Path $logDir "bench_results.csv"

"Harness,Result,ElapsedSec,PeakMemMB,Flags" | Out-File $csvPath -Encoding utf8

function Invoke-Bench {
    param(
        [string]$Name,
        [string]$File,
        [string[]]$EsbmcArgs,
        [string[]]$ExtraSources = @()
    )
    $log    = Join-Path $logDir "$Name.log"
    $sources = @($File) + $ExtraSources
    $argLine = ($sources + $EsbmcArgs) -join " "
    "Command: $EsbmcPath $argLine`n" | Out-File $log -Encoding utf8

    $peakMem = 0
    $elapsed = $null

    $elapsed = (Measure-Command {
        $proc = Start-Process -FilePath $EsbmcPath `
            -ArgumentList ($sources + $EsbmcArgs) `
            -NoNewWindow -PassThru -RedirectStandardOutput "$log.stdout" -RedirectStandardError "$log.stderr"

        # Poll peak working set while ESBMC is running
        while (-not $proc.HasExited) {
            try {
                $proc.Refresh()
                $ws = $proc.PeakWorkingSet64
                if ($ws -gt $peakMem) { $peakMem = $ws }
            } catch {}
            Start-Sleep -Milliseconds 200
        }
        $proc.WaitForExit()
    }).TotalSeconds

    # Merge stdout/stderr into main log
    if (Test-Path "$log.stdout") { Get-Content "$log.stdout" | Out-File $log -Append -Encoding utf8 }
    if (Test-Path "$log.stderr") { Get-Content "$log.stderr" | Out-File $log -Append -Encoding utf8 }
    Remove-Item "$log.stdout","$log.stderr" -ErrorAction SilentlyContinue

    $resultLine = Select-String -Path $log -Pattern "VERIFICATION (SUCCESSFUL|FAILED)" | Select-Object -Last 1
    $result = if ($resultLine) { ($resultLine.Line -replace '.*VERIFICATION ','').Trim() } else { "UNKNOWN" }
    $peakMB  = [math]::Round($peakMem / 1MB, 1)
    $elapsedR = [math]::Round($elapsed, 2)
    $flagsSummary = ($EsbmcArgs -join " ") -replace '"',''

    Write-Host ("{0,-55} {1,-12} {2,8}s  {3,7}MB" -f $Name, $result, $elapsedR, $peakMB)
    "$Name,$result,$elapsedR,$peakMB,`"$flagsSummary`"" | Out-File $csvPath -Append -Encoding utf8
}

$u8  = @("--unwind", "8",  "--no-unwinding-assertions")
$u16 = @("--unwind", "16", "--no-unwinding-assertions")
$u32 = @("--unwind", "32", "--no-unwinding-assertions")
$u4  = @("--unwind", "4",  "--no-unwinding-assertions")
$net = @("esbmc_models\network_stubs.c")

Write-Host ("=" * 80)
Write-Host ("ESBMC Benchmark - Eclipse Mosquitto Harnesses")
Write-Host ("ESBMC: $EsbmcPath")
Write-Host ("Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
Write-Host ("=" * 80)
Write-Host ("{0,-55} {1,-12} {2,9}  {3,8}" -f "Harness", "Result", "Time(s)", "Mem(MB)")
Write-Host ("-" * 80)

# --- Isolated harnesses ---
Invoke-Bench "remaining_length_vulnerable" `
    "harnesses\mosquitto\remaining_length_harness.c" `
    ($u8 + "--unsigned-overflow-check")

Invoke-Bench "connect_memleak_vulnerable" `
    "harnesses\mosquitto\connect_memleak_harness.c" `
    ($u16 + "--memory-leak-check")

Invoke-Bench "read_binary_obo_vulnerable" `
    "harnesses\mosquitto\read_binary_obo_harness.c" $u8

Invoke-Bench "acl_bypass_vulnerable" `
    "harnesses\mosquitto\acl_bypass_harness.c" $u32

Invoke-Bench "acl_bypass_fixed" `
    "harnesses\mosquitto\acl_bypass_harness_fixed.c" $u32

Invoke-Bench "will_properties_vulnerable" `
    "harnesses\mosquitto\will_properties_memleak_harness.c" `
    ($u8 + "--memory-leak-check")

Invoke-Bench "will_properties_fixed" `
    "harnesses\mosquitto\will_properties_memleak_harness_fixed.c" `
    ($u8 + "--memory-leak-check")

Invoke-Bench "initial_packet_vulnerable" `
    "harnesses\mosquitto\initial_packet_state_harness.c" `
    @("--unwind", "4")

Invoke-Bench "initial_packet_fixed" `
    "harnesses\mosquitto\initial_packet_state_harness_fixed.c" `
    @("--unwind", "4")

Invoke-Bench "qos2_dup_vulnerable" `
    "harnesses\mosquitto\qos2_dup_leak_harness.c" `
    ($u8 + "--memory-leak-check")

Invoke-Bench "qos2_dup_fixed" `
    "harnesses\mosquitto\qos2_dup_leak_harness_fixed.c" $u8

Invoke-Bench "bridge_remap_vulnerable" `
    "harnesses\mosquitto\bridge_remap_double_free_harness.c" `
    @("--unwind", "16", "--no-unwinding-assertions", "--memory-leak-check")

Invoke-Bench "bridge_remap_fixed" `
    "harnesses\mosquitto\bridge_remap_double_free_harness_fixed.c" `
    @("--unwind", "16", "--no-unwinding-assertions", "--memory-leak-check")

Invoke-Bench "varint_properties" `
    "harnesses\mosquitto\varint_harness.c" $u8

Invoke-Bench "max_packet_size_properties" `
    "harnesses\mosquitto\max_packet_size_harness.c" $u8

# --- Integration harnesses (use network_stubs.c) ---
Invoke-Bench "packet_recv_remaining_length_vulnerable" `
    "harnesses\mosquitto\packet_recv_remaining_length_harness.c" `
    ($u8 + "--unsigned-overflow-check") -ExtraSources $net

Invoke-Bench "packet_recv_remaining_length_fixed" `
    "harnesses\mosquitto\packet_recv_remaining_length_harness_fixed.c" `
    $u8 -ExtraSources $net

Invoke-Bench "packet_recv_initial_command_vulnerable" `
    "harnesses\mosquitto\packet_recv_initial_command_harness.c" `
    $u4 -ExtraSources $net

Invoke-Bench "packet_recv_initial_command_fixed" `
    "harnesses\mosquitto\packet_recv_initial_command_harness_fixed.c" `
    $u4 -ExtraSources $net

Invoke-Bench "proxy_v2_tlv_vulnerable" `
    "harnesses\mosquitto\proxy_v2_tlv_harness.c" `
    @("--unsigned-overflow-check")

Invoke-Bench "proxy_v2_tlv_fixed" `
    "harnesses\mosquitto\proxy_v2_tlv_harness_fixed.c" `
    @("--unsigned-overflow-check")

Write-Host ("=" * 80)
Write-Host "Benchmark complete. Results: $csvPath"
