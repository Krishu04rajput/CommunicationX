#!/usr/bin/env python3
"""
Direct server startup script that bypasses gunicorn issues
Ensures HTTP and WebSocket requests are handled properly
"""

import os
import sys
import logging
from werkzeug.serving import run_simple
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# Import the Flask app with all routes
from app import app, socketio
import routes  # noqa: F401
import socket_events  # noqa: F401

# Register blueprints
from advanced_routes import advanced
app.register_blueprint(advanced, url_prefix='/api/advanced')

try:
    from tools_routes import tools
    app.register_blueprint(tools, url_prefix='/tools')
    print("Tools routes registered successfully")
except Exception as e:
    print(f"Error registering tools routes: {e}")

if __name__ == '__main__':
    print("Starting CommunicationX with real-time messaging...")
    print("Server accessible at http://0.0.0.0:5000")
    
    # Use Werkzeug development server for better HTTP handling
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        use_reloader=False,
        log_output=True
    )