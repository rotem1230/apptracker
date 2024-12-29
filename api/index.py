from flask import Flask
import sys
import os

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# This is needed for Vercel serverless deployment
app.debug = False

# For Vercel, we need to export the app object
application = app
