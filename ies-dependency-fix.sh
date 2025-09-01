#!/bin/bash
# IES Dependency Fix Script
# Run this inside the LXC container to fix missing Python dependencies

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
msg_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }

msg_info "IES Dependency Fix - Resolving Python module issues"

# Check if we're in the right directory
if [[ ! -f "/opt/IES/military_database_analyzer_v3.py" ]]; then
    msg_error "IES application not found at /opt/IES/"
    msg_info "Please run this script inside the LXC container with IES installed"
    exit 1
fi

# Navigate to IES directory
cd /opt/IES

# Check if virtual environment exists
if [[ ! -d "ies_env" ]]; then
    msg_warn "Virtual environment not found, creating new one..."
    python3 -m venv ies_env
fi

# Activate virtual environment
msg_info "Activating virtual environment..."
source ies_env/bin/activate

# Update pip first
msg_info "Updating pip..."
pip install --upgrade pip

# Install all required dependencies explicitly
msg_info "Installing required Python packages..."

# Core scientific computing and data analysis
pip install --upgrade numpy pandas matplotlib seaborn scipy

# Network analysis
pip install --upgrade networkx

# Plotting and visualization
pip install --upgrade plotly

# Machine learning
pip install --upgrade scikit-learn

# Web framework and utilities
pip install --upgrade flask jinja2 gunicorn

# Monitoring and metrics
pip install --upgrade prometheus-client psutil

# Additional utilities
pip install --upgrade requests urllib3 jsonschema

# Try requirements.txt if it exists
if [[ -f "requirements.txt" ]]; then
    msg_info "Installing from requirements.txt..."
    pip install -r requirements.txt || msg_warn "Some packages from requirements.txt failed to install"
fi

# Verify installations
msg_info "Verifying critical dependencies..."

# Test imports
python3 -c "
import sys
failed_imports = []

# Test critical packages
try:
    import networkx
    print(f'✓ networkx: {networkx.__version__}')
except ImportError as e:
    failed_imports.append('networkx')
    print(f'✗ networkx: FAILED')

try:
    import pandas
    print(f'✓ pandas: {pandas.__version__}')
except ImportError:
    failed_imports.append('pandas')
    print(f'✗ pandas: FAILED')

try:
    import numpy
    print(f'✓ numpy: {numpy.__version__}')
except ImportError:
    failed_imports.append('numpy')
    print(f'✗ numpy: FAILED')

try:
    import matplotlib
    print(f'✓ matplotlib: {matplotlib.__version__}')
except ImportError:
    failed_imports.append('matplotlib')
    print(f'✗ matplotlib: FAILED')

try:
    import seaborn
    print(f'✓ seaborn: {seaborn.__version__}')
except ImportError:
    failed_imports.append('seaborn')
    print(f'✗ seaborn: FAILED')

try:
    import plotly
    print(f'✓ plotly: {plotly.__version__}')
except ImportError:
    failed_imports.append('plotly')
    print(f'✗ plotly: FAILED')

try:
    import flask
    print(f'✓ flask: {flask.__version__}')
except ImportError:
    failed_imports.append('flask')
    print(f'✗ flask: FAILED')

try:
    import sklearn
    print(f'✓ scikit-learn: {sklearn.__version__}')
except ImportError:
    failed_imports.append('scikit-learn')
    print(f'✗ scikit-learn: FAILED')

if failed_imports:
    print(f'\\nFailed imports: {failed_imports}')
    sys.exit(1)
else:
    print('\\nAll critical dependencies verified successfully!')
"

if [[ $? -ne 0 ]]; then
    msg_error "Some dependencies are still missing. Attempting force reinstall..."
    pip install --force-reinstall networkx pandas numpy matplotlib seaborn plotly flask scikit-learn
    
    # Test again
    python3 -c "import networkx, pandas, numpy, matplotlib, seaborn, plotly, flask, sklearn; print('Force reinstall successful!')" || {
        msg_error "Force reinstall failed. Manual intervention required."
        exit 1
    }
fi

# Test main application import
msg_info "Testing main application import..."
python3 -c "
import sys
sys.path.append('/opt/IES')
try:
    from military_database_analyzer_v3 import MilitaryDatabaseAnalyzer
    print('✓ Main application import successful')
except ImportError as e:
    print(f'✗ Main application import failed: {e}')
    sys.exit(1)
"

if [[ $? -ne 0 ]]; then
    msg_error "Main application import failed. Checking for missing modules..."
    
    # Try to identify missing modules from the error
    msg_info "Attempting to identify missing dependencies..."
    python3 -c "
import sys
sys.path.append('/opt/IES')

# Check individual src modules
modules_to_check = [
    'src.graph_builder',
    'src.data_processor', 
    'src.analysis_engine',
    'src.web_interface'
]

for module in modules_to_check:
    try:
        exec(f'import {module}')
        print(f'✓ {module}')
    except ImportError as e:
        print(f'✗ {module}: {e}')
    except Exception as e:
        print(f'? {module}: {e}')
" || true
    
    msg_warn "Check the above output for specific missing modules"
fi

# Create a verification script for future use
cat > verify_dependencies.py << 'EOF'
#!/usr/bin/env python3
"""
IES Dependency Verification Script
Run this to check if all required dependencies are available
"""

import sys
import importlib

# Required modules
REQUIRED_MODULES = [
    'networkx',
    'pandas', 
    'numpy',
    'matplotlib',
    'seaborn',
    'plotly',
    'flask',
    'sklearn',
    'jinja2',
    'prometheus_client',
    'psutil'
]

# Optional modules (nice to have)
OPTIONAL_MODULES = [
    'requests',
    'jsonschema',
    'gunicorn',
    'scipy'
]

def check_module(module_name):
    try:
        mod = importlib.import_module(module_name)
        version = getattr(mod, '__version__', 'unknown')
        return True, version
    except ImportError:
        return False, None

def main():
    print("IES Dependency Verification")
    print("=" * 40)
    
    all_good = True
    
    print("\nRequired Dependencies:")
    for module in REQUIRED_MODULES:
        available, version = check_module(module)
        status = "✓" if available else "✗"
        version_str = f" (v{version})" if version and version != 'unknown' else ""
        print(f"  {status} {module}{version_str}")
        if not available:
            all_good = False
    
    print("\nOptional Dependencies:")
    for module in OPTIONAL_MODULES:
        available, version = check_module(module)
        status = "✓" if available else "○"
        version_str = f" (v{version})" if version and version != 'unknown' else ""
        print(f"  {status} {module}{version_str}")
    
    print("\nIES Application Modules:")
    ies_modules = [
        'src.graph_builder',
        'src.data_processor', 
        'src.analysis_engine',
        'src.web_interface'
    ]
    
    sys.path.append('/opt/IES')
    for module in ies_modules:
        available, _ = check_module(module)
        status = "✓" if available else "✗"
        print(f"  {status} {module}")
        if not available:
            all_good = False
    
    print("\n" + "=" * 40)
    if all_good:
        print("✓ All required dependencies are available!")
        return 0
    else:
        print("✗ Some required dependencies are missing!")
        print("\nTo fix missing Python packages, run:")
        print("  cd /opt/IES")
        print("  source ies_env/bin/activate")
        print("  pip install <missing_package_name>")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x verify_dependencies.py

# Restart the IES service to apply changes
msg_info "Restarting IES service..."
systemctl restart ies-analyzer

# Wait a moment and check service status
sleep 5
if systemctl is-active --quiet ies-analyzer; then
    msg_ok "IES service is running successfully"
else
    msg_warn "IES service may have issues. Check logs with: journalctl -u ies-analyzer"
fi

# Final verification
msg_info "Running final verification..."
./verify_dependencies.py

msg_ok "Dependency fix completed!"
msg_info "If issues persist, check the service logs: journalctl -u ies-analyzer -f"
msg_info "Use the verification script anytime: /opt/IES/verify_dependencies.py"