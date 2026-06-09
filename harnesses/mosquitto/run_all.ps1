# Run all Mosquitto ESBMC harnesses and write logs.
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

function Invoke-Harness {
    param(
        [string]$Name,
        [string]$File,
        [string[]]$EsbmcArgs,
        [string[]]$ExtraSources = @()
    )
    $log = Join-Path $logDir "$Name.log"
    $sources = @($File) + $ExtraSources
    $argLine = ($sources + $EsbmcArgs) -join " "
    "Command: $EsbmcPath $argLine`n" | Out-File $log -Encoding utf8
    & $EsbmcPath @sources @EsbmcArgs 2>&1 | Out-File $log -Append -Encoding utf8
    $result = Select-String -Path $log -Pattern "VERIFICATION (SUCCESSFUL|FAILED)" | Select-Object -Last 1
    Write-Host "$Name -> $($result.Line)"
}

$u8 = @("--unwind", "8", "--no-unwinding-assertions")
$u16 = @("--unwind", "16", "--no-unwinding-assertions")
$u32 = @("--unwind", "32", "--no-unwinding-assertions")
$u4 = @("--unwind", "4", "--no-unwinding-assertions")
$netStubs = @("esbmc_models\network_stubs.c")

Invoke-Harness "remaining_length_vulnerable" "harnesses\mosquitto\remaining_length_harness.c" ($u8 + "--unsigned-overflow-check")
Invoke-Harness "connect_memleak_vulnerable" "harnesses\mosquitto\connect_memleak_harness.c" ($u16 + "--memory-leak-check")
Invoke-Harness "read_binary_obo_vulnerable" "harnesses\mosquitto\read_binary_obo_harness.c" $u8
Invoke-Harness "acl_bypass_vulnerable" "harnesses\mosquitto\acl_bypass_harness.c" $u32
Invoke-Harness "acl_bypass_fixed" "harnesses\mosquitto\acl_bypass_harness_fixed.c" $u32
Invoke-Harness "will_properties_vulnerable" "harnesses\mosquitto\will_properties_memleak_harness.c" ($u8 + "--memory-leak-check")
Invoke-Harness "will_properties_fixed" "harnesses\mosquitto\will_properties_memleak_harness_fixed.c" ($u8 + "--memory-leak-check")
Invoke-Harness "initial_packet_vulnerable" "harnesses\mosquitto\initial_packet_state_harness.c" (@("--unwind", "4"))
Invoke-Harness "initial_packet_fixed" "harnesses\mosquitto\initial_packet_state_harness_fixed.c" (@("--unwind", "4"))
Invoke-Harness "qos2_dup_vulnerable" "harnesses\mosquitto\qos2_dup_leak_harness.c" ($u8 + "--memory-leak-check")
Invoke-Harness "qos2_dup_fixed" "harnesses\mosquitto\qos2_dup_leak_harness_fixed.c" $u8
Invoke-Harness "bridge_remap_vulnerable" "harnesses\mosquitto\bridge_remap_double_free_harness.c" (@("--unwind", "16", "--no-unwinding-assertions", "--memory-leak-check"))
Invoke-Harness "bridge_remap_fixed" "harnesses\mosquitto\bridge_remap_double_free_harness_fixed.c" (@("--unwind", "16", "--no-unwinding-assertions", "--memory-leak-check"))
Invoke-Harness "varint_properties" "harnesses\mosquitto\varint_harness.c" $u8
Invoke-Harness "max_packet_size_properties" "harnesses\mosquitto\max_packet_size_harness.c" $u8
Invoke-Harness "packet_recv_remaining_length_vulnerable" `
    "harnesses\mosquitto\packet_recv_remaining_length_harness.c" `
    ($u8 + "--unsigned-overflow-check") `
    -ExtraSources $netStubs
Invoke-Harness "packet_recv_remaining_length_fixed" `
    "harnesses\mosquitto\packet_recv_remaining_length_harness_fixed.c" `
    $u8 `
    -ExtraSources $netStubs
Invoke-Harness "packet_recv_initial_command_vulnerable" `
    "harnesses\mosquitto\packet_recv_initial_command_harness.c" `
    $u4 `
    -ExtraSources $netStubs
Invoke-Harness "packet_recv_initial_command_fixed" `
    "harnesses\mosquitto\packet_recv_initial_command_harness_fixed.c" `
    $u4 `
    -ExtraSources $netStubs
Invoke-Harness "proxy_v2_tlv_vulnerable" `
    "harnesses\mosquitto\proxy_v2_tlv_harness.c" `
    @("--unsigned-overflow-check")
Invoke-Harness "proxy_v2_tlv_fixed" `
    "harnesses\mosquitto\proxy_v2_tlv_harness_fixed.c" `
    @("--unsigned-overflow-check")

Write-Host "Done. Logs in $logDir"
