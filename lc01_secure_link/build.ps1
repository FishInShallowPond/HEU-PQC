param([string]$ToolchainRoot='D:\Config Files\MSYS2\ucrt64',[switch]$SkipIntegration)
$ErrorActionPreference='Stop'
$projectRoot=$PSScriptRoot
$env:PATH=(Join-Path $ToolchainRoot 'bin')+';'+$env:PATH
$cmake=Join-Path $ToolchainRoot 'bin\cmake.exe'
$buildRoot=Join-Path $projectRoot 'build'
$binRoot=Join-Path $projectRoot 'bin'
& $cmake -S $projectRoot -B $buildRoot -G Ninja '-DCMAKE_BUILD_TYPE=Release' "-DCMAKE_C_COMPILER=$ToolchainRoot/bin/gcc.exe" "-DOPENSSL_ROOT_DIR=$ToolchainRoot"
if($LASTEXITCODE){throw 'CMake configure failed'}
& $cmake --build $buildRoot
if($LASTEXITCODE){throw 'Compilation failed'}
Copy-Item -LiteralPath (Join-Path $ToolchainRoot 'bin\libcrypto-3-x64.dll') -Destination $buildRoot -Force
& (Join-Path $ToolchainRoot 'bin\ctest.exe') --test-dir $buildRoot --output-on-failure
if($LASTEXITCODE){throw 'Core tests failed'}
New-Item -ItemType Directory -Path $binRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $buildRoot 'LC01_Secure_Link_v0.exe') -Destination $binRoot -Force
& (Join-Path $ToolchainRoot 'bin\strip.exe') --strip-unneeded (Join-Path $binRoot 'LC01_Secure_Link_v0.exe')
if($LASTEXITCODE){throw 'Release symbol stripping failed'}
Copy-Item -LiteralPath (Join-Path $ToolchainRoot 'bin\libcrypto-3-x64.dll') -Destination $binRoot -Force
Copy-Item -LiteralPath (Join-Path $ToolchainRoot 'share\licenses\openssl\LICENSE') -Destination (Join-Path $binRoot 'LICENSE-OpenSSL.txt') -Force
$selfTest=Start-Process -FilePath (Join-Path $binRoot 'LC01_Secure_Link_v0.exe') -ArgumentList '--self-test' -PassThru -Wait
$selfTest.Refresh()
if($selfTest.ExitCode -ne 0){throw "Packaged self-test failed ($($selfTest.ExitCode))"}
$guiSmoke=Start-Process -FilePath (Join-Path $binRoot 'LC01_Secure_Link_v0.exe') -ArgumentList '--gui-smoke' -PassThru -Wait
$guiSmoke.Refresh()
if($guiSmoke.ExitCode -ne 0){throw "Packaged GUI smoke failed ($($guiSmoke.ExitCode))"}
if(!$SkipIntegration){
    # The console launcher exposes the same endpoint implementation for scripted tests.
    # The release GUI EXE is separately exercised by --self-test and --gui-smoke.
    & (Join-Path $projectRoot 'tests\run_integration.ps1') -Exe (Join-Path $buildRoot 'test_endpoint.exe')
    if($LASTEXITCODE){throw 'Two-process integration tests failed'}
}
$hash=(Get-FileHash -LiteralPath (Join-Path $binRoot 'LC01_Secure_Link_v0.exe') -Algorithm SHA256).Hash
"$hash  LC01_Secure_Link_v0.exe" | Set-Content -LiteralPath (Join-Path $binRoot 'LC01_Secure_Link_v0.exe.sha256') -Encoding ascii
Write-Output "SHA256 $hash"
