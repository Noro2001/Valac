# Python Setup for Windows

## Problem
The `python` command doesn't work, but `py` works. This happens due to Windows App Execution Aliases.

## Solution 1: Use `py` (Quick Fix)

Instead of `python`, use `py`:

```powershell
# Instead of: python valac.py
py valac.py

# Instead of: python -m pip install
py -m pip install

# Instead of: python --version
py --version
```

## Solution 2: Disable App Execution Aliases (Recommended)

1. Open **Windows Settings** (Win + I)
2. Go to **Apps** → **Advanced features** → **App execution aliases**
3. Find **App Installer** or **Python**
4. Disable aliases for `python.exe` and `python3.exe`

Or via PowerShell (requires administrator rights):

```powershell
# Disable App Execution Aliases for Python
Remove-Item "$env:LOCALAPPDATA\Microsoft\WindowsApps\python.exe" -ErrorAction SilentlyContinue
Remove-Item "$env:LOCALAPPDATA\Microsoft\WindowsApps\python3.exe" -ErrorAction SilentlyContinue
```

## Solution 3: Add Python to PATH

1. Find Python path:
   ```powershell
   py -c "import sys; print(sys.executable)"
   ```

2. Add path to system PATH variable:
   - Open **Control Panel** → **System** → **Advanced system settings**
   - Click **Environment Variables**
   - In **System variables**, find `Path` and click **Edit**
   - Add Python path (usually `C:\Users\<username>\AppData\Local\Programs\Python\Python313\`)
   - Add Scripts path (usually `C:\Users\<username>\AppData\Local\Programs\Python\Python313\Scripts\`)

Or via PowerShell (requires administrator rights):

```powershell
# Get Python path
$pythonPath = py -c "import sys; import os; print(os.path.dirname(sys.executable))"
$scriptsPath = Join-Path $pythonPath "Scripts"

# Add to PATH for current user
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$pythonPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$pythonPath;$scriptsPath", "User")
    Write-Host "Python added to PATH. Restart terminal."
}
```

## Solution 4: Create PowerShell Alias

Add to your PowerShell profile (`$PROFILE`):

```powershell
# Create alias python -> py
Set-Alias -Name python -Value py
Set-Alias -Name python3 -Value py
```

To create profile if it doesn't exist:

```powershell
if (!(Test-Path -Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force
}
notepad $PROFILE
```

Then add the lines above and save.

## Verification

After applying any solution, verify:

```powershell
python --version
# Should show: Python 3.13.1
```

## For Valac Project

All commands in README.md can be used with `py` instead of `python`:

```powershell
# Install dependencies
py -m pip install -r requirements.txt

# Run scanner
py valac.py scan --ip 8.8.8.8

# Or use alias (after setup)
python valac.py scan --ip 8.8.8.8
```
