"""
Vercel entry point for CommunicationX.

Vercel imports `app` from this file and uses it as the WSGI application.
"""

import os

# Make sure the project root is importable.
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

# Vercel / WSGI entry point
application = app
