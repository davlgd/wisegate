#!/bin/bash

# Quick WiseGate Test Script
# Builds and runs a basic functionality test

set -e

echo "🔨 Building WiseGate..."
cargo build --release

echo "🧪 Running quick functionality test..."

# Start a simple HTTP server in background
python3 -c "
import http.server
import socketserver
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Backend OK')
    def log_message(self, format, *args): pass
with socketserver.TCPServer(('localhost', 9999), Handler) as httpd:
    httpd.serve_forever()
" &
BACKEND_PID=$!

# Give backend time to start
sleep 1

# Start WiseGate in quiet mode
./target/release/wisegate -l 8899 -f 9999 --quiet &
WISEGATE_PID=$!

# Give WiseGate time to start
sleep 1

# Test the connection
echo "📡 Testing connection..."
RESPONSE=$(curl -s http://localhost:8899/ || echo "FAILED")

# Cleanup
kill $BACKEND_PID $WISEGATE_PID 2>/dev/null || true

# Check result
if [ "$RESPONSE" = "Backend OK" ]; then
    echo "✅ Test PASSED: WiseGate successfully proxied the request"
    echo "🚀 Your build is working correctly!"
else
    echo "❌ Test FAILED: Expected 'Backend OK', got: $RESPONSE"
    exit 1
fi