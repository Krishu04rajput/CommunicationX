#!/usr/bin/env python3
"""
Clean startup script for CommunicationX
Bypasses all Gunicorn/eventlet conflicts
"""

import os
import sys

# Remove eventlet from the environment to prevent conflicts
if 'eventlet' in sys.modules:
    del sys.modules['eventlet']

from app import app

if __name__ == '__main__':
    print("Starting CommunicationX with clean Flask configuration...")
    print("DM messaging and 500MB file uploads enabled")
    print("Server available at http://0.0.0.0:5000")
    
    # Use Flask's built-in server for reliability
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True,
        use_reloader=False
    )