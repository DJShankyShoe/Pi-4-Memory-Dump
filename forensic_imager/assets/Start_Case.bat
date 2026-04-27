@echo off
echo Start_Case version 2026-04-27f
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
  set "FORENSICS_ELEVATION_REQUESTED=1"
  echo Requesting Administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b 0
)

set "TOOLS_DIR=%~dp0"
set "TOOLS_DRIVE=%~d0"
set "TOOL_PATH=%TOOLS_DIR%tools\winpmem.exe"
set "REQUEST_CERT=%TOOLS_DIR%cert\pub.cer"
set "CONTROL_VERIFY_URL=http://169.254.2.1:8080/verify-password"
set "CONTROL_START_URL=http://169.254.2.1:8080/start-case"
set "CONTROL_ACQ_START_URL=http://169.254.2.1:8080/acquisition-started"
set "CONTROL_EVENT_URL=http://169.254.2.1:8080/session-event"
set "CONTROL_STATUS_URL=http://169.254.2.1:8080/status"
set "CONTROL_FINALIZE_URL=http://169.254.2.1:8080/finalize"

if not exist "%TOOL_PATH%" (
  echo winpmem.exe not found at "%TOOL_PATH%"
  pause
  exit /b 1
)
if not exist "%REQUEST_CERT%" (
  echo pub.cer not found at "%REQUEST_CERT%"
  pause
  exit /b 1
)

call :prompt_hidden_password
if errorlevel 1 (
  pause
  exit /b 1
)

echo.
echo Verifying password...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop'; " ^
  "try { " ^
  "  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%REQUEST_CERT%'); " ^
  "  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert); " ^
  "  $salt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt); " ^
  "  $data = [ordered]@{password=$env:LUKS_PASSWORD; salt_b64=[Convert]::ToBase64String($salt); requested_utc=[DateTime]::UtcNow.ToString('o')}; " ^
  "  $json = $data | ConvertTo-Json -Compress; " ^
  "  $cipher = $rsa.Encrypt([System.Text.Encoding]::UTF8.GetBytes($json), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256); " ^
  "  $body = [ordered]@{algorithm='RSA-OAEP-SHA256'; encrypted_request_b64=[Convert]::ToBase64String($cipher)} | ConvertTo-Json -Compress; " ^
  "  Invoke-RestMethod -Uri '%CONTROL_VERIFY_URL%' -Method Post -ContentType 'application/json' -Body $body > $null; " ^
  "} catch { exit 1 }"
if %errorlevel% neq 0 (
  echo Authentication failed.
  pause
  exit /b %errorlevel%
)

echo Password verified.
set /p CASE_ID=Enter case ID:
set /p OPERATOR_ID=Enter operator ID:
set /p TARGET_HOST=Enter target hostname:
set /p NOTES=Enter notes (optional):

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop'; try { $body = @{ case_id=$env:CASE_ID; operator_id=$env:OPERATOR_ID; target_host=$env:TARGET_HOST; notes=$env:NOTES } | ConvertTo-Json -Compress; Invoke-RestMethod -Uri '%CONTROL_START_URL%' -Method Post -ContentType 'application/json' -Body $body > $null } catch { exit 1 }"
if %errorlevel% neq 0 (
  echo Case setup failed.
  pause
  exit /b %errorlevel%
)

set /a WAIT_COUNT=0
:wait_for_stage_ready
call :refresh_stage_paths
if "%STAGE_READY%"=="1" goto stage_ready
set /a WAIT_COUNT+=1
if %WAIT_COUNT% geq 120 (
  echo Timed out waiting for the dump volume.
  pause
  exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_for_stage_ready

:stage_ready
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo.
echo Starting memory acquisition. Do not use this machine until it completes.
echo.
call :report_event "dump_collection_started" "tool=winpmem" "output=%OUTPUT_FILE%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop'; " ^
  "$tool = '%TOOL_PATH%'; " ^
  "$outFile = '%OUTPUT_FILE%'; " ^
  "$stdoutPath = [System.IO.Path]::GetTempFileName(); " ^
  "$stderrPath = [System.IO.Path]::GetTempFileName(); " ^
  "$ramBytes = [int64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; " ^
  "if ($ramBytes -lt 1) { $ramBytes = 1L } " ^
  "if (Test-Path $outFile) { Remove-Item -LiteralPath $outFile -Force } " ^
  "$proc = Start-Process -FilePath $tool -ArgumentList @('acquire','--progress','--nosparse',$outFile) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden; " ^
  "$lastPct = -1; " ^
  "while (-not $proc.HasExited) { " ^
  "  $size = 0L; if (Test-Path $outFile) { $size = [int64](Get-Item $outFile).Length } " ^
  "  $pct = [Math]::Min(99, [int](($size * 100L) / $ramBytes)); " ^
  "  if ($pct -ne $lastPct) { Write-Host (([char]13) + 'Acquisition progress: ' + $pct + '%%   ') -NoNewline; $lastPct = $pct } " ^
  "  Start-Sleep -Milliseconds 500; " ^
  "  $proc.Refresh(); " ^
  "} " ^
  "$size = 0L; if (Test-Path $outFile) { $size = [int64](Get-Item $outFile).Length } " ^
  "$pct = if ($proc.ExitCode -eq 0) { 100 } else { [Math]::Min(100, [int](($size * 100L) / $ramBytes)) }; " ^
  "Write-Host (([char]13) + 'Acquisition progress: ' + $pct + '%%   '); " ^
  "Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue; " ^
  "exit $proc.ExitCode"
if %errorlevel% neq 0 (
  call :output_file_has_data
  if "%OUTPUT_HAS_DATA%"=="1" (
    echo.
    echo winpmem exited with error code %errorlevel%, but the dump file was created.
    echo Continuing to finalization.
  ) else (
    echo winpmem exited with error code %errorlevel%
    pause
    exit /b %errorlevel%
  )
)
call :report_event "dump_collection_completed" "output=%OUTPUT_FILE%"

echo.
echo Acquisition complete. Finalizing...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop'; " ^
  "try { " ^
  "  $body = '{}'; " ^
  "  Invoke-RestMethod -Uri '%CONTROL_FINALIZE_URL%' -Method Post -ContentType 'application/json' -Body $body > $null; " ^
  "  $lastPct = -1; " ^
  "  while ($true) { " ^
  "    $status = Invoke-RestMethod -Uri '%CONTROL_STATUS_URL%' -Method Get; " ^
  "    if ($status.last_error) { exit 1 } " ^
  "    $pct = 0; if ($status.progress) { $pct = [int]$status.progress.percent }; " ^
  "    if ($pct -ne $lastPct) { Write-Host (([char]13) + 'Finalizing on Raspberry Pi: ' + $pct + '%%   ') -NoNewline; $lastPct = $pct } " ^
  "    if ($status.status -eq 'LOCKED_IDLE' -and $status.last_result) { " ^
  "      Write-Host (([char]13) + 'Finalizing on Raspberry Pi: 100%%   '); " ^
  "      Write-Host 'Acquisition finalized successfully.'; " ^
  "      Write-Host ('Case ID: ' + $status.last_result.case_id); " ^
  "      Write-Host ('Session ID: ' + $status.last_result.session_id); " ^
  "      Write-Host ('SHA-512: ' + $status.last_result.sha512); " ^
  "      break; " ^
  "    } " ^
  "    Start-Sleep -Seconds 1; " ^
  "  } " ^
  "} catch { " ^
  "  try { " ^
  "    $status = Invoke-RestMethod -Uri '%CONTROL_STATUS_URL%' -Method Get; " ^
  "    if ($status.status -eq 'LOCKED_IDLE' -and -not $status.last_result) { " ^
  "      Write-Host ''; " ^
  "      Write-Host 'Session was interrupted or discarded on the Raspberry Pi.'; " ^
  "      exit 2; " ^
  "    } " ^
  "  } catch { } " ^
  "  exit 1 " ^
  "}"
if %errorlevel% neq 0 (
  if %errorlevel% equ 2 (
    echo Finalization did not complete. The interrupted session was discarded.
  ) else (
    echo Finalization request failed.
  )
  pause
  exit /b %errorlevel%
)
pause
exit /b 0

:prompt_hidden_password
set "LUKS_PASSWORD="
powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'Enter LUKS password: ' -NoNewline"
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$chars = New-Object System.Collections.Generic.List[char]; " ^
  "while ($true) { " ^
  "  $key = [Console]::ReadKey($true); " ^
  "  if ($key.Key -eq [ConsoleKey]::Enter) { break } " ^
  "  if ($key.Key -eq [ConsoleKey]::Backspace) { if ($chars.Count -gt 0) { $chars.RemoveAt($chars.Count - 1) }; continue } " ^
  "  if (-not [char]::IsControl($key.KeyChar)) { [void]$chars.Add($key.KeyChar) } " ^
  "} " ^
  "[Console]::WriteLine(); " ^
  "-join $chars"`) do set "LUKS_PASSWORD=%%I"
if not defined LUKS_PASSWORD (
  echo No password entered.
  exit /b 1
)
exit /b 0

:refresh_stage_paths
set "STAGE_READY=0"
set "CURRENT_STAGE_DRIVE="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$dl = (Get-Volume -FileSystemLabel 'F_DUMP' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DriveLetter); if ($null -ne $dl) { $dl.ToString().Trim() }"`) do set "CURRENT_STAGE_DRIVE=%%I"
set "CURRENT_STAGE_DRIVE=%CURRENT_STAGE_DRIVE: =%"
if "%CURRENT_STAGE_DRIVE%"=="" exit /b 0
if not exist "%CURRENT_STAGE_DRIVE%:\" exit /b 0
set "STAGE_DRIVE=%CURRENT_STAGE_DRIVE%"
set "STAGE_ROOT=%STAGE_DRIVE%:\"
set "OUTPUT_DIR=%STAGE_ROOT%output"
set "OUTPUT_FILE=%OUTPUT_DIR%\memory.raw"
if not exist "%OUTPUT_DIR%" exit /b 0
set "STAGE_READY=1"
exit /b 0

:output_file_has_data
set "OUTPUT_HAS_DATA=0"
for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$dl = (Get-Volume -FileSystemLabel 'F_DUMP' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DriveLetter); if ($null -ne $dl) { $path = $dl + ':\output\memory.raw'; if ((Test-Path $path) -and ((Get-Item $path).Length -gt 0)) { '1' } else { '0' } } else { '0' }"`) do set "OUTPUT_HAS_DATA=%%I"
exit /b 0

:report_event
set "EVENT_NAME=%~1"
set "EVENT_ARG2=%~2"
set "EVENT_ARG3=%~3"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop'; " ^
  "$body = @{ event='%EVENT_NAME%' }; " ^
  "if ('%EVENT_ARG2%') { $kv = '%EVENT_ARG2%'.Split('=',2); if ($kv.Length -eq 2) { $body[$kv[0]] = $kv[1] } } " ^
  "if ('%EVENT_ARG3%') { $kv = '%EVENT_ARG3%'.Split('=',2); if ($kv.Length -eq 2) { $body[$kv[0]] = $kv[1] } } " ^
  "try { Invoke-RestMethod -Uri '%CONTROL_EVENT_URL%' -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) > $null } catch { exit 0 }"
exit /b 0
