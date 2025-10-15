# CVD-Detect Deployment Guide

## Quick Deployment Options

### 🚀 Option 1: Render (Recommended - FREE)
1. Go to [render.com](https://render.com)
2. Connect your GitHub repository
3. Use the `render.yaml` file (already created)
4. Your app will be live at: `https://your-app-name.onrender.com`

### 🚂 Option 2: Railway (FREE tier)
1. Go to [railway.app](https://railway.app)
2. Connect your GitHub repository
3. Use the `railway.json` file (already created)
4. Your app will be live at: `https://your-app-name.up.railway.app`

### 🟣 Option 3: Heroku (FREE tier limited)
1. Install Heroku CLI
2. Run: 
   ```bash
   heroku create your-app-name
   git push heroku main
   ```
3. Your app will be live at: `https://your-app-name.herokuapp.com`

### ⚡ Option 4: Vercel (FREE)
1. Go to [vercel.com](https://vercel.com)
2. Connect your GitHub repository
3. Use the `vercel.json` file (already created)
4. Your app will be live at: `https://your-app-name.vercel.app`

## Environment Variables to Set

For any platform, make sure to set these environment variables:

- `SECRET_KEY`: A secure random string
- `GOOGLE_API_KEY`: Your Google API key (if using AI features)
- `FLASK_ENV`: Set to `production`
- `PORT`: Usually auto-detected by hosting platforms

## Pre-deployment Checklist

✅ All configuration files created
✅ Requirements.txt updated
✅ Static files properly configured
✅ Database initialization handled
✅ Error handlers implemented

## Getting Your Web Link

After deployment, your CVD-Detect project will be accessible at:
- Render: `https://cvd-detect.onrender.com`
- Railway: `https://cvd-detect.up.railway.app`  
- Heroku: `https://cvd-detect.herokuapp.com`
- Vercel: `https://cvd-detect.vercel.app`

Replace `cvd-detect` with your chosen app name.

## Features Available via Web Link

Your hosted application will provide:
- 🛡️ Vulnerability scanning dashboard
- 📊 Real-time threat analysis
- 🤖 AI-powered security chat assistant
- 📈 Comprehensive security reports
- 🔍 CVE database integration
- 📋 Export functionality for scan results

## Support

If you encounter any issues during deployment, check the platform-specific logs and ensure all environment variables are properly set.