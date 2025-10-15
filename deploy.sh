#!/bin/bash

echo "🚀 CVD-Detect Quick Deployment Script"
echo "======================================"

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "Initializing Git repository..."
    git init
    git add .
    git commit -m "Initial commit - CVD Detection System"
fi

echo ""
echo "Choose your deployment platform:"
echo "1) Render (render.com) - Recommended"
echo "2) Railway (railway.app)"
echo "3) Heroku (heroku.com)"
echo "4) Vercel (vercel.com)"
echo ""

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo "🎯 Deploying to Render..."
        echo "1. Go to https://render.com"
        echo "2. Connect your GitHub repository"
        echo "3. Your app will be live at: https://your-app-name.onrender.com"
        echo "✅ render.yaml configuration file is ready!"
        ;;
    2)
        echo "🚂 Deploying to Railway..."
        echo "1. Go to https://railway.app"
        echo "2. Connect your GitHub repository"
        echo "3. Your app will be live at: https://your-app-name.up.railway.app"
        echo "✅ railway.json configuration file is ready!"
        ;;
    3)
        echo "🟣 Deploying to Heroku..."
        if command -v heroku &> /dev/null; then
            read -p "Enter your app name: " app_name
            heroku create $app_name
            echo "Push to Heroku with: git push heroku main"
            echo "Your app will be live at: https://$app_name.herokuapp.com"
        else
            echo "Please install Heroku CLI first: https://devcenter.heroku.com/articles/heroku-cli"
        fi
        echo "✅ Procfile configuration file is ready!"
        ;;
    4)
        echo "⚡ Deploying to Vercel..."
        echo "1. Go to https://vercel.com"
        echo "2. Connect your GitHub repository"
        echo "3. Your app will be live at: https://your-app-name.vercel.app"
        echo "✅ vercel.json configuration file is ready!"
        ;;
    *)
        echo "Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""
echo "🌟 Next Steps:"
echo "1. Push your code to GitHub"
echo "2. Connect your repository to your chosen platform"
echo "3. Set environment variables (SECRET_KEY, GOOGLE_API_KEY, etc.)"
echo "4. Your CVD Detection System will be live!"
echo ""
echo "📖 See DEPLOYMENT.md for detailed instructions"