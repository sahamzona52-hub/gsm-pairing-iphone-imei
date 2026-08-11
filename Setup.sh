#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                     PegasusMetaSec Installation                            ║"
echo "║                    Complete GSM Security Suite                            ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv pegasus_env
source pegasus_env/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install rich cryptography colorama

# Create launcher
echo "🚀 Creating launcher..."
cat > pegasus << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source pegasus_env/bin/activate
python3 pegasusmetasec.py "$@"
EOF
chmod +x pegasus

echo ""
echo "✅ Installation Complete!"
echo ""
echo "📱 To run PegasusMetaSec:"
echo "   ./pegasus"
echo ""
echo "⚠️  LEGAL NOTICE: This tool is for authorized security testing only"
