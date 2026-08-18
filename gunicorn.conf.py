import multiprocessing

bind = "0.0.0.0:5000"
workers = 1
worker_class = "eventlet"
worker_connections = 1000
timeout = 300
keepalive = 2
preload_app = False
max_requests = 0
max_requests_jitter = 0
reload = True
reload_extra_files = ["templates/", "static/"]