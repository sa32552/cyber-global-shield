"""
Cyber Global Shield v2.0 — Entry point for Render/Uvicorn
This file avoids the module conflict between app.py and the app/ package directory.
"""
import sys
import os

# Ensure the current directory is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the FastAPI app from app.py
from app import app as application

app = application
