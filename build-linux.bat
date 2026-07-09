@echo off
setlocal

set CGO_ENABLED=0
set GOOS=linux

echo Building hbot-linux-amd64...
set GOARCH=amd64
go build -buildvcs=false -trimpath -ldflags="-s -w" -o hbot-linux-amd64 .
if errorlevel 1 (
  echo Failed to build hbot-linux-amd64.
  exit /b 1
)

echo Building hbot-linux-arm64...
set GOARCH=arm64
go build -buildvcs=false -trimpath -ldflags="-s -w" -o hbot-linux-arm64 .
if errorlevel 1 (
  echo Failed to build hbot-linux-arm64.
  exit /b 1
)

echo Done.
echo   hbot-linux-amd64
echo   hbot-linux-arm64

endlocal
