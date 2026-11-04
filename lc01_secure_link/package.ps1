param([string]$OutputDirectory=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
$projectRoot=$PSScriptRoot
$stageRoot=Join-Path $env:TEMP ('lc01-v0-package-'+[guid]::NewGuid().ToString('N'))
$stageProject=Join-Path $stageRoot 'lc01_secure_link'
New-Item -ItemType Directory -Path $stageProject -Force | Out-Null
foreach($entry in @('bin','src','include','docs','README.md','CMakeLists.txt','build.ps1','build.cmd','package.ps1')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot $entry) -Destination $stageProject -Recurse -Force
}
$stagedTests=Join-Path $stageProject 'tests'
New-Item -ItemType Directory -Path $stagedTests -Force | Out-Null
foreach($testFile in @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'tests') -File | Where-Object { $_.Extension -in @('.c','.ps1') })) {
    Copy-Item -LiteralPath $testFile.FullName -Destination $stagedTests -Force
}
$manifest=@{
    product='LC01 Secure Link';version='v0';createdUtc=[datetime]::UtcNow.ToString('o');
    hardwareValidated=$false;mcuValidated=$false;energyMeasured=$false;qkdImplemented=$false;
    files=@(Get-ChildItem -LiteralPath $stageProject -File -Recurse | ForEach-Object {
        @{path=$_.FullName.Substring($stageProject.Length+1).Replace('\','/');size=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stageProject 'release-manifest-v0.json') -Encoding utf8
$stagedExe=Join-Path $stageProject 'bin\LC01_Secure_Link_v0.exe'
$selfTest=Start-Process -FilePath $stagedExe -ArgumentList '--self-test' -PassThru -Wait
$selfTest.Refresh()
if($selfTest.ExitCode -ne 0){throw "Staged self-test failed ($($selfTest.ExitCode))"}
$guiSmoke=Start-Process -FilePath $stagedExe -ArgumentList '--gui-smoke' -PassThru -Wait
$guiSmoke.Refresh()
if($guiSmoke.ExitCode -ne 0){throw "Staged GUI smoke failed ($($guiSmoke.ExitCode))"}
$archivePath=Join-Path $OutputDirectory 'LC01_Secure_Link_Windows_v0.zip'
Compress-Archive -LiteralPath $stageProject -DestinationPath $archivePath -Force
$hash=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
($hash+'  '+[IO.Path]::GetFileName($archivePath)) | Set-Content -LiteralPath ($archivePath+'.sha256') -Encoding ascii
Get-Item -LiteralPath $archivePath
Write-Output ('SHA256 '+$hash)
Write-Output ('Reviewable package staging directory: '+$stageProject)
