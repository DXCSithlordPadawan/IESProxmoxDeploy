#!/bin/bash
# IES Application Diagnosis Script
# Run this to determine why you're not seeing the expected Bootstrap interface

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}IES Application Diagnosis${NC}"
echo "========================="
echo

# Check if we're in the container
echo "1. Environment Check:"
echo "--------------------"
if [[ -f "/opt/IES/military_database_analyzer_v3.py" ]]; then
    echo -e "✓ In IES container"
else
    echo -e "✗ Not in IES container - run 'pct enter 351' first"
    exit 1
fi

echo "Current directory: $(pwd)"
echo "Container IP: $(hostname -I | awk '{print $1}')"
echo

# Check service status
echo "2. Service Status:"
echo "-----------------"
if systemctl is-active --quiet ies-analyzer; then
    echo -e "✓ IES service is running"
else
    echo -e "✗ IES service is not running"
    echo "  To start: systemctl start ies-analyzer"
fi

if systemctl is-active --quiet nginx; then
    echo -e "✓ Nginx is running"
else
    echo -e "✗ Nginx is not running"
    echo "  To start: systemctl start nginx"
fi
echo

# Check what's listening on port 8000
echo "3. Port Check:"
echo "-------------"
if netstat -tlnp 2>/dev/null | grep -q ":8000"; then
    echo -e "✓ Something is listening on port 8000"
    netstat -tlnp 2>/dev/null | grep ":8000" | head -1
else
    echo -e "✗ Nothing listening on port 8000"
fi
echo

# Check the current application file
echo "4. Application File Check:"
echo "-------------------------"
cd /opt/IES
if [[ -f "military_database_analyzer_v3.py" ]]; then
    echo -e "✓ Application file exists"
    
    # Check if it contains Bootstrap
    if grep -q "bootstrap" military_database_analyzer_v3.py; then
        echo -e "✓ Application file contains Bootstrap code"
    else
        echo -e "✗ Application file does NOT contain Bootstrap code"
        echo "  This is likely why you're seeing the simple interface"
    fi
    
    # Check if it contains the IES4 title
    if grep -q "IES4 Military Database Analysis Suite" military_database_analyzer_v3.py; then
        echo -e "✓ Application file contains IES4 title"
    else
        echo -e "✗ Application file does NOT contain IES4 title"
    fi
else
    echo -e "✗ Application file missing"
fi
echo

# Check Python environment
echo "5. Python Environment:"
echo "---------------------"
if [[ -d "ies_env" ]]; then
    echo -e "✓ Virtual environment exists"
    source ies_env/bin/activate
    
    # Check Flask
    if python3 -c "import flask" 2>/dev/null; then
        echo -e "✓ Flask is installed"
        flask_version=$(python3 -c "import flask; print(flask.__version__)" 2>/dev/null)
        echo "  Flask version: $flask_version"
    else
        echo -e "✗ Flask is NOT installed"
        echo "  To install: pip install flask"
    fi
    
    # Check other dependencies
    missing=()
    for pkg in jinja2 plotly pandas numpy; do
        if python3 -c "import $pkg" 2>/dev/null; then
            echo -e "✓ $pkg is available"
        else
            echo -e "✗ $pkg is missing"
            missing+=($pkg)
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "  To install missing packages: pip install ${missing[*]}"
    fi
else
    echo -e "✗ Virtual environment missing"
fi
echo

# Test the application directly
echo "6. Direct Application Test:"
echo "--------------------------"
cd /opt/IES
if [[ -f "ies_env/bin/activate" ]]; then
    source ies_env/bin/activate
    
    echo "Testing application import..."
    if python3 -c "from military_database_analyzer_v3 import MilitaryDatabaseAnalyzer" 2>/dev/null; then
        echo -e "✓ Application imports successfully"
    else
        echo -e "✗ Application import failed"
        echo "Error details:"
        python3 -c "from military_database_analyzer_v3 import MilitaryDatabaseAnalyzer" 2>&1 | head -5
    fi
fi
echo

# Test web endpoints
echo "7. Endpoint Testing:"
echo "-------------------"
# Test health endpoint
if curl -s -f http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo -e "✓ Health endpoint responding"
    health_response=$(curl -s http://127.0.0.1:8000/health)
    echo "  Response: $health_response"
else
    echo -e "✗ Health endpoint not responding"
fi

# Test main page and check content
echo "Testing main page content..."
main_content=$(curl -s http://127.0.0.1:8000/ 2>/dev/null)
if echo "$main_content" | grep -q "IES4 Military Database Analysis Suite"; then
    echo -e "✓ Main page shows IES4 Bootstrap interface"
elif echo "$main_content" | grep -q "IES Military Database Analyzer"; then
    echo -e "⚠ Main page shows basic interface (not Bootstrap)"
    echo "  Title found: $(echo "$main_content" | grep -o '<title>[^<]*</title>' | sed 's/<[^>]*>//g')"
else
    echo -e "✗ Main page not responding or showing unexpected content"
fi
echo

# Check recent service logs
echo "8. Recent Service Logs:"
echo "----------------------"
echo "Last 5 log entries for ies-analyzer service:"
journalctl -u ies-analyzer --no-pager -n 5 2>/dev/null || echo "Could not retrieve service logs"
echo

# Provide recommendations
echo "9. Recommendations:"
echo "------------------"
if ! systemctl is-active --quiet ies-analyzer; then
    echo "• Start the IES service: systemctl start ies-analyzer"
fi

if ! grep -q "bootstrap" /opt/IES/military_database_analyzer_v3.py 2>/dev/null; then
    echo "• Your application file needs to be updated with the Bootstrap interface"
    echo "• Run the fix script to replace it with the full version"
fi

if ! python3 -c "import flask" 2>/dev/null; then
    echo "• Install missing Python packages: cd /opt/IES && source ies_env/bin/activate && pip install flask jinja2"
fi

echo "• Clear browser cache and hard refresh the page (Ctrl+F5 or Cmd+Shift+R)"
echo "• If issues persist, restart the service: systemctl restart ies-analyzer"

echo
echo "To run the fix script that will update your application:"
echo "curl -s https://raw.githubusercontent.com/path/to/fix-script.sh | bash"
echo
echo "Or create and run the fix script provided earlier in this conversation."
