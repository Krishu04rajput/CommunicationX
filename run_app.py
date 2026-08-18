#!/usr/bin/env python3
"""
Direct Flask application runner
Bypasses gunicorn issues and runs Flask with proper threading support
"""
import sys
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Import the Flask app
from app import app
import routes  # noqa: F401
import socket_events  # noqa: F401

# Register blueprints
from advanced_routes import advanced
app.register_blueprint(advanced, url_prefix='/api/advanced')

try:
    from tools_routes import tools
    app.register_blueprint(tools, url_prefix='/tools')
    logging.info("Tools routes registered successfully")
except Exception as e:
    logging.error(f"Error registering tools routes: {e}")

if __name__ == '__main__':
    logging.info("Starting CommunicationX Flask server...")
    logging.info("Server will be available at http://0.0.0.0:5000")
    
    # Run Flask with threading support
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # Disable debug to prevent reloader issues
        threaded=True,
        use_reloader=False,
        use_debugger=False
    )