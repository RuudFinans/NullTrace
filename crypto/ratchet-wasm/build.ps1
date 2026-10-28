param(
    [string]$Cargo = "cargo",
    [string]$WasmBindgen = (Join-Path $PSScriptRoot ".tools/bin/wasm-bindgen.exe")
)
$ErrorActionPreference = "Stop"
$manifest = Join-Path $PSScriptRoot "Cargo.toml"
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$assets = Join-Path $workspace "frontend/static/libs/ratchet-wasm"
if (-not (Test-Path -LiteralPath $WasmBindgen)) { $WasmBindgen = "wasm-bindgen" }
$version = & $WasmBindgen --version
if ($LASTEXITCODE -ne 0 -or $version -ne "wasm-bindgen 0.2.129") {
    throw "The build requires wasm-bindgen-cli 0.2.129."
}
& $Cargo build --manifest-path $manifest --target wasm32-unknown-unknown --release --locked
if ($LASTEXITCODE -ne 0) { throw "Rust WASM build failed." }
$wasm = Join-Path $PSScriptRoot "target/wasm32-unknown-unknown/release/nulltrace_ratchet.wasm"
& $WasmBindgen $wasm --target web --out-dir $assets --out-name nulltrace_ratchet --no-typescript
if ($LASTEXITCODE -ne 0) { throw "wasm-bindgen failed." }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "vendor/vodozemac/LICENSE") -Destination (Join-Path $assets "LICENSE.vodozemac")
$lines = foreach ($name in @("nulltrace_ratchet.js", "nulltrace_ratchet_bg.wasm")) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $assets $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name"
}
[IO.File]::WriteAllLines((Join-Path $assets "SHA256SUMS"), $lines, [Text.UTF8Encoding]::new($false))
