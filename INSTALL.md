# Installation Instructions

## Quick Install

If you're using a virtual environment (`.venv`), activate it first:

### Windows (PowerShell):
```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Windows (CMD):
```cmd
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

### Linux/Mac:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## If Virtual Environment is Not Activated

If you see `ModuleNotFoundError`, make sure your virtual environment is activated.

### Check if venv is active:
- You should see `(.venv)` in your terminal prompt
- If not, activate it using the commands above

### Install dependencies:
```bash
pip install -r requirements.txt
```

## Manual Install

If you prefer to install packages individually:

```bash
pip install tqdm>=4.65.0
pip install requests>=2.31.0,<3
pip install urllib3>=2.0.0
pip install aiohttp>=3.8.0
pip install aiodns>=3.0.0
pip install dnspython>=2.0.0
pip install psutil>=5.9.0
```

**Note:** `psutil` is optional but recommended for resource monitoring. The tool will work without it, but memory monitoring features will be disabled.

## Verify Installation

After installation, verify tqdm is installed:

```bash
python -c "import tqdm; print('tqdm installed successfully')"
```

## Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'tqdm'`

**Solution 1:** Make sure virtual environment is activated
```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install tqdm
```

**Solution 2:** Install in the virtual environment directly
```powershell
.venv\Scripts\python.exe -m pip install tqdm
```

**Solution 3:** If using global Python, install globally
```powershell
py -m pip install tqdm
```

### Issue: `pip is not recognized`

**Solution:** Use Python module syntax
```powershell
python -m pip install tqdm
# or
py -m pip install tqdm
```

