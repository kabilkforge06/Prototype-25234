# 🎯 Centralized Vulnerability Detection & Intelligent Query Interface

## Overview
An integrated AI-powered cybersecurity platform that consolidates vulnerability scanning tools (Nmap, OpenVAS, Nessus, Nikto, Nuclei) with intelligent threat analysis using Google Gemini and LangChain RAG.

## 🚀 Features

### Phase 1: Vulnerability Scanning
- **Multi-tool Integration**: Nmap, OpenVAS, Nessus, Nikto, Nuclei
- **Responsive Web GUI**: Modern dashboard for scan management
- **Real-time Progress**: Live scanning status and updates

### Phase 2: Intelligence & Correlation
- **CVE Correlation**: Automatic matching with NVD database
- **CVSS Scoring**: Risk prioritization and impact assessment
- **Attack Path Generation**: MITRE ATT&CK framework integration
- **Threat Intelligence**: ExploitDB, Rapid7, CISA KEV integration

### Phase 3: AI-Powered Analysis
- **RAG Chatbot**: Google Gemini with LangChain implementation
- **Natural Language Queries**: Ask questions about vulnerabilities
- **Contextual Responses**: Exploit steps and remediation guidance
- **Multi-user Support**: Concurrent chatbot interactions

## 🛠 Technology Stack

- **Backend**: Python Flask, SQLAlchemy, PostgreSQL
- **AI/ML**: LangChain, Google Gemini, ChromaDB, FAISS
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Scanners**: Nmap, OpenVAS, Nessus, Nikto, Nuclei
- **Containerization**: Docker, Docker Compose
- **Task Queue**: Celery with Redis

## 📋 Prerequisites

- Python 3.9+
- Docker & Docker Compose
- PostgreSQL 13+
- Redis Server
- Google API Key (for Gemini)

### System Requirements
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 20GB for vulnerability databases
- **Network**: Internet access for threat intelligence feeds

## 🚀 Quick Start

### 1. Clone & Setup
```bash
git clone <repository-url>
cd centralized-vulnerability-detection
cp .env.example .env
```

### 2. Configure Environment
Edit `.env` file:
```env
GOOGLE_API_KEY=your_gemini_api_key_here
DATABASE_URL=postgresql://user:pass@localhost:5432/vuln_db
REDIS_URL=redis://localhost:6379/0
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup
```bash
python -m flask db init
python -m flask db migrate
python -m flask db upgrade
```

### 5. Start Services
```bash
# Using Docker Compose (Recommended)
docker-compose up -d

# Or manually
python app/main.py
```

### 6. Access Application
- **Web Interface**: http://localhost:5000
- **API Documentation**: http://localhost:5000/docs
- **Admin Panel**: http://localhost:5000/admin

## 📖 Usage Guide

### Starting a Vulnerability Scan
1. Navigate to the dashboard
2. Enter target (IP, domain, or network range)
3. Select scanning tools (Nmap, OpenVAS, etc.)
4. Click "Start Scan"
5. Monitor progress in real-time

### Using the AI Chatbot
1. Go to the Chat interface
2. Ask questions like:
   - "What are the critical vulnerabilities?"
   - "How do I exploit CVE-2023-12345?"
   - "Show me attack paths for high-risk hosts"
3. Get intelligent responses with references

### Generating Reports
1. Select completed scans
2. Choose report format (PDF, JSON, XML)
3. Download structured vulnerability reports

## 🏗 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Frontend  │◄──►│  Flask Backend   │◄──►│   PostgreSQL    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │  Scanner Tools   │
                    │ Nmap│OpenVAS│... │
                    └──────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │   RAG System     │
                    │ Gemini│LangChain │
                    └──────────────────┘
```

## 🔧 Configuration

### Scanner Tools Setup
- **Nmap**: Pre-installed with python-nmap
- **OpenVAS**: Configure in `scanners/openvas_client.py`
- **Nessus**: Add API keys in environment variables
- **Nikto**: Command-line integration
- **Nuclei**: Template-based scanning

### AI Configuration
- **Google Gemini**: Set `GOOGLE_API_KEY` in .env
- **Vector Database**: ChromaDB for embeddings
- **Knowledge Base**: Automatic threat intelligence updates

## 🧪 Testing

```bash
# Run all tests
pytest

# Test specific components
pytest tests/test_scanners.py
pytest tests/test_rag.py
pytest tests/test_api.py

# Coverage report
pytest --cov=app tests/
```

## 📊 API Endpoints

### Scanning APIs
- `POST /api/scans/start` - Start vulnerability scan
- `GET /api/scans/{id}/status` - Check scan progress
- `GET /api/scans/{id}/results` - Get scan results

### Vulnerability APIs
- `GET /api/vulnerabilities` - List all vulnerabilities
- `GET /api/vulnerabilities/{id}` - Get vulnerability details
- `POST /api/vulnerabilities/search` - Search vulnerabilities

### Chat APIs
- `POST /api/chat/query` - Send query to AI chatbot
- `GET /api/chat/history` - Get chat history
- `DELETE /api/chat/clear` - Clear chat session

## 🔒 Security Considerations

- **Data Encryption**: All sensitive data encrypted at rest
- **API Authentication**: JWT-based authentication system
- **Input Validation**: Comprehensive input sanitization
- **Rate Limiting**: API rate limiting implemented
- **Audit Logging**: Complete audit trail for all actions

## 📈 Performance Optimization

- **Async Processing**: Celery for background tasks
- **Database Indexing**: Optimized queries for large datasets
- **Caching**: Redis caching for frequent queries
- **Connection Pooling**: Database connection optimization

## 🚀 Deployment

### Production Deployment
```bash
# Build production image
docker build -t vuln-detector .

# Deploy with scaling
docker-compose -f docker-compose.prod.yml up -d --scale worker=3
```

### Environment-specific Configs
- **Development**: `config/dev.py`
- **Testing**: `config/test.py`
- **Production**: `config/prod.py`

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙋‍♂️ Support

- **Documentation**: `/docs` folder
- **Issues**: GitHub Issues tracker
- **Email**: support@vulndetector.com

## 🗺 Roadmap

### v1.0 (Current)
- ✅ Basic vulnerability scanning
- ✅ Google Gemini RAG integration
- ✅ Web dashboard

### v1.1 (Next Release)
- 🔄 Advanced attack path visualization
- 🔄 Compliance reporting (SOX, HIPAA, PCI-DSS)
- 🔄 Mobile application

### v2.0 (Future)
- 📋 Machine learning for false positive reduction
- 📋 Integration with SIEM/SOAR platforms
- 📋 Enterprise SSO support

---

**Built with ❤️ for SIH 2025 Hackathon**