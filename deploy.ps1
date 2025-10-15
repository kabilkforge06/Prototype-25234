# CVD-Detect Quick Deployment Script for Windows
# Run this in PowerShell

Write-Host "🚀 CVD-Detect Quick Deployment Script" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Check if git is initialized
if (-not (Test-Path ".git")) {
    Write-Host "Initializing Git repository..." -ForegroundColor Yellow
    git init
    git add .
    git commit -m "Initial commit - CVD Detection System"
}

Write-Host ""
Write-Host "Choose your deployment platform:" -ForegroundColor Green
Write-Host "1) Render (render.com) - Recommended" -ForegroundColor White
Write-Host "2) Railway (railway.app)" -ForegroundColor White
Write-Host "3) Heroku (heroku.com)" -ForegroundColor White
Write-Host "4) Vercel (vercel.com)" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter your choice (1-4)"

switch ($choice) {
    1 {
        Write-Host "🎯 Deploying to Render..." -ForegroundColor Magenta
        Write-Host "1. Go to https://render.com" -ForegroundColor White
        Write-Host "2. Connect your GitHub repository" -ForegroundColor White
        Write-Host "3. Your app will be live at: https://your-app-name.onrender.com" -ForegroundColor White
        Write-Host "✅ render.yaml configuration file is ready!" -ForegroundColor Green
    }
    2 {
        Write-Host "🚂 Deploying to Railway..." -ForegroundColor Blue
        Write-Host "1. Go to https://railway.app" -ForegroundColor White
        Write-Host "2. Connect your GitHub repository" -ForegroundColor White
        Write-Host "3. Your app will be live at: https://your-app-name.up.railway.app" -ForegroundColor White
        Write-Host "✅ railway.json configuration file is ready!" -ForegroundColor Green
    }
    3 {
        Write-Host "🟣 Deploying to Heroku..." -ForegroundColor DarkMagenta
        if (Get-Command heroku -ErrorAction SilentlyContinue) {
            $app_name = Read-Host "Enter your app name"
            heroku create $app_name
            Write-Host "Push to Heroku with: git push heroku main" -ForegroundColor Yellow
            Write-Host "Your app will be live at: https://$app_name.herokuapp.com" -ForegroundColor White
        } else {
            Write-Host "Please install Heroku CLI first: https://devcenter.heroku.com/articles/heroku-cli" -ForegroundColor Red
        }
        Write-Host "✅ Procfile configuration file is ready!" -ForegroundColor Green
    }
    4 {
        Write-Host "⚡ Deploying to Vercel..." -ForegroundColor Yellow
        Write-Host "1. Go to https://vercel.com" -ForegroundColor White
        Write-Host "2. Connect your GitHub repository" -ForegroundColor White
        Write-Host "3. Your app will be live at: https://your-app-name.vercel.app" -ForegroundColor White
        Write-Host "✅ vercel.json configuration file is ready!" -ForegroundColor Green
    }
    default {
        Write-Host "Invalid choice. Please run the script again." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "🌟 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Push your code to GitHub" -ForegroundColor White
Write-Host "2. Connect your repository to your chosen platform" -ForegroundColor White
Write-Host "3. Set environment variables (SECRET_KEY, GOOGLE_API_KEY, etc.)" -ForegroundColor White
Write-Host "4. Your CVD Detection System will be live!" -ForegroundColor White
Write-Host ""
Write-Host "📖 See DEPLOYMENT.md for detailed instructions" -ForegroundColor Green

# Keep window open
Read-Host "Press Enter to continue"