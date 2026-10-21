@echo off
rem Infrastructure Lab: one-click launcher for a source checkout on Windows.
rem   launch.cmd            install dependencies and build if needed, then start the app
rem   launch.cmd --rebuild  rebuild first (use after updating the source)
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js 20 or newer is required. Install the LTS version from https://nodejs.org and run launch.cmd again.
  pause
  exit /b 1
)
node -e "process.exit(Number(process.versions.node.split('.')[0]) >= 20 ? 0 : 1)"
if errorlevel 1 (
  echo Your Node.js is too old. Install version 20 or newer from https://nodejs.org and run launch.cmd again.
  pause
  exit /b 1
)

if not exist "node_modules\.bin\electron.cmd" (
  echo ==^> Installing dependencies ^(first run only, downloads the Electron runtime^)...
  call npm ci --no-audit --no-fund
  if errorlevel 1 ( pause & exit /b 1 )
)

set NEED_BUILD=0
if not exist "dist\index.html" set NEED_BUILD=1
if /i "%~1"=="--rebuild" set NEED_BUILD=1
if "%NEED_BUILD%"=="1" (
  echo ==^> Building the app...
  call npm run build
  if errorlevel 1 ( pause & exit /b 1 )
)

echo ==^> Starting Infrastructure Lab...
node scripts\electron-launch.cjs .
