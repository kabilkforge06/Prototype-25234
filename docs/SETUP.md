# Setup Guide

## Prerequisites

1. **Python 3.9+**
2. **PostgreSQL 13+**
3. **Redis Server**
4. **Docker & Docker Compose** (recommended)
5. **Google API Key** for Gemini

## Quick Setup with Docker

1. Clone the repository:
```bash
git clone <repository-url>
cd centralized-vulnerability-detection
```

2. Copy environment file:
```bash
cp .env.example .env
```

3. Edit `.env` and add your Google Gemini API key:
```bash
GOOGLE_API_KEY=your_actual_api_key_here
```

4. Start services:
```bash
docker-compose up -d
```

5. Access the application:
- Web Interface: http://localhost:5000
- API Health Check: http://localhost:5000/health

## Manual Setup

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Setup PostgreSQL database:
```bash
createdb vuln_detector
```

3. Start Redis server:
```bash
redis-server
```

4. Initialize database:
```bash
python -c "from app.main import db; db.create_all()"
```

5. Run the application:
```bash
python app/main.py
```

## Getting Google Gemini API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Create a new API key
4. Copy the key and add it to your `.env` file

## Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Ensure PostgreSQL is running
   - Check DATABASE_URL in .env file

2. **Google Gemini API Error**
   - Verify API key is correct
   - Check API quota limits

3. **Scanner Tools Not Found**
   - Install nmap: `sudo apt-get install nmap`
   - Install nikto: `sudo apt-get install nikto`

### Log Files

- Application logs: `logs/vuln_detector.log`
- Docker logs: `docker-compose logs`

## Next Steps

1. Configure scanner tools
2. Add threat intelligence sources
3. Customize vulnerability detection rules
4. Set up automated scanning schedules
