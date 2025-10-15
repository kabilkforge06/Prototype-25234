#!/bin/bash

# Centralized Vulnerability Detection - Run Script

echo "🎯 Starting Centralized Vulnerability Detection Platform"
echo "============================================="

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Copying from .env.example..."
    cp .env.example .env
    echo "📝 Please edit .env file with your Google Gemini API key and other settings"
    exit 1
fi

# Check if Docker is available
if command -v docker-compose &> /dev/null; then
    echo "🐳 Starting services with Docker Compose..."
    docker-compose up -d

    echo "⏳ Waiting for services to start..."
    sleep 10

    echo "✅ Services started successfully!"
    echo ""
    echo "🌐 Web Interface: http://localhost:5000"
    echo "🤖 AI Assistant: http://localhost:5000/chat"
    echo "📊 API Health: http://localhost:5000/health"
    echo ""
    echo "To stop services: docker-compose down"

elif command -v python3 &> /dev/null; then
    echo "🐍 Starting with Python..."

    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        echo "📦 Creating virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Install dependencies
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt

    # Start the application
    echo "🚀 Starting application..."
    python app/main.py

else
    echo "❌ Neither Docker nor Python3 found. Please install one of them."
    exit 1
fi