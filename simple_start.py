
#!/usr/bin/env python3
"""
Simple startup script for CommunicationX
Uses Flask-SocketIO's built-in server for reliable WebSocket connections
"""

import os
import sys

if __name__ == '__main__':
    print("Starting CommunicationX with Flask-SocketIO server...")
    print("DM messaging and real-time features enabled")
    print("Server available at http://0.0.0.0:5000")

    # Import app and register all routes
    from app import app, socketio
    import routes  # This registers all the URL routes
    import socket_events  # This registers socket event handlers

    # Register additional blueprints
    try:
        from advanced_routes import advanced
        app.register_blueprint(advanced, url_prefix='/api/advanced')
        print("Advanced routes registered")
    except Exception as e:
        print(f"Could not register advanced routes: {e}")

    try:
        from tools_routes import tools
        app.register_blueprint(tools, url_prefix='/tools')
        print("Tools routes registered")
    except Exception as e:
        print(f"Could not register tools routes: {e}")

    print("All routes registered successfully")

    # Use Flask-SocketIO's run method for stable connections
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
        log_output=True
    )
