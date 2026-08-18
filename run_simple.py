#!/usr/bin/env python3
"""
Simple Flask server without complex SocketIO configuration
"""

import os
from flask import Flask
from app import app

if __name__ == '__main__':
    print("Starting CommunicationX on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)