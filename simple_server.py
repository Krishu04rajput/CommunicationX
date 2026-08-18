#!/usr/bin/env python3
"""
Simple Flask server for real-time messaging
Runs without gunicorn to avoid worker timeout issues
"""

import os
import sys
import logging
from flask import Flask
from flask_socketio import SocketIO
from app import app, socketio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_simple_server():
    """Run the Flask app with SocketIO using development server"""
    try:
        logger.info("Starting simple server for real-time messaging...")
        logger.info("Server will be available at http://0.0.0.0:5000")
        
        # Run with SocketIO
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=5000, 
                    debug=False,
                    allow_unsafe_werkzeug=True,
                    use_reloader=False)
                    
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_simple_server()