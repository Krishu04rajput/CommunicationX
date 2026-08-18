import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import inspect as sqlalchemy_inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s - %(message)s"
)


# ============================================================
# DATABASE BASE
# ============================================================

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "dev-secret-key-change-in-production"
)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_proto=1,
    x_host=1
)


# ============================================================
# SECURITY
# ============================================================

app.config["WTF_CSRF_ENABLED"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 3600


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

database_url = os.environ.get("DATABASE_URL", "").strip()

if database_url:

    # Convert old postgres:// URLs to postgresql://
    if database_url.startswith("postgres://"):
        database_url = "postgresql://" + database_url[len("postgres://"):]

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_size": 5,
        "max_overflow": 2,
    }

else:

    # Local development fallback
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///communicationx.db"
    )

    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}


app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# ============================================================
# FILE UPLOAD
# ============================================================

app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024


# ============================================================
# RATE LIMITING
# ============================================================

limiter = None


# ============================================================
# INITIALIZE DATABASE
# ============================================================

db.init_app(app)


# ============================================================
# SOCKET.IO
# ============================================================

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
    allow_upgrades=True,
    transports=["websocket", "polling"],
)


# ============================================================
# DATABASE TYPE
# ============================================================

def is_postgresql():
    """
    Return True when the application is using PostgreSQL.
    """
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")

    return (
        uri.startswith("postgresql://")
        or uri.startswith("postgresql+")
        or uri.startswith("postgres://")
    )


# ============================================================
# DATABASE SCHEMA CHECK
# ============================================================

def check_database_schema():
    """
    Check whether the important database columns exist.

    This function does NOT modify the database.
    """

    try:

        inspector = sqlalchemy_inspect(db.engine)

        table_names = set(
            inspector.get_table_names()
        )

        # If the table doesn't exist,
        # create_all()/migration must handle it.
        if "server_membership" not in table_names:
            return False

        columns = {
            column["name"]
            for column in inspector.get_columns(
                "server_membership"
            )
        }

        required_columns = {
            "custom_status",
            "activity_status",
            "boost_count",
            "flags",
        }

        return required_columns.issubset(columns)

    except Exception as e:

        app.logger.warning(
            f"Schema check failed: {e}"
        )

        return False


# ============================================================
# MIGRATION DEFINITIONS
# ============================================================

MIGRATION_COLUMNS = {

    "server_membership": [

        ("custom_status", "VARCHAR(128)"),

        (
            "activity_status",
            "VARCHAR(20) DEFAULT 'online'"
        ),

        (
            "boost_count",
            "INTEGER DEFAULT 0"
        ),

        (
            "flags",
            "INTEGER DEFAULT 0"
        ),

        (
            "is_admin",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "can_manage_server",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "can_manage_channels",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "can_kick_members",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "can_ban_members",
            "BOOLEAN DEFAULT FALSE"
        ),
    ],


    "server": [

        (
            "password_hash",
            "VARCHAR(256)"
        ),

        (
            "password_enabled",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "password_set_by",
            "INTEGER"
        ),

        (
            "password_set_at",
            "TIMESTAMP"
        ),

        (
            "is_locked",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "locked_by",
            "INTEGER"
        ),

        (
            "locked_at",
            "TIMESTAMP"
        ),

        (
            "lock_reason",
            "TEXT"
        ),
    ],


    "users": [

        (
            "is_admin",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "is_super_admin",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "admin_permissions",
            "TEXT"
        ),

        (
            "is_banned",
            "BOOLEAN DEFAULT FALSE"
        ),

        (
            "ban_reason",
            "TEXT"
        ),

        (
            "banned_by",
            "INTEGER"
        ),

        (
            "banned_at",
            "TIMESTAMP"
        ),
    ],
}


# ============================================================
# RUN MIGRATION
# ============================================================

def run_migration():
    """
    Create missing tables and add missing columns.

    Safe for PostgreSQL and SQLite.
    """

    try:

        with app.app_context():

            # First create tables defined by SQLAlchemy models.
            db.create_all()

            inspector = sqlalchemy_inspect(
                db.engine
            )

            existing_tables = set(
                inspector.get_table_names()
            )

            print("Checking database migrations...")

            for table_name, columns in MIGRATION_COLUMNS.items():

                if table_name not in existing_tables:
                    print(
                        f"Skipping {table_name}: table does not exist."
                    )
                    continue

                existing_columns = {
                    column["name"]
                    for column in inspector.get_columns(
                        table_name
                    )
                }

                for column_name, column_definition in columns:

                    if column_name in existing_columns:
                        continue

                    print(
                        f"Adding {table_name}.{column_name}..."
                    )

                    # PostgreSQL and SQLite both support
                    # ALTER TABLE ADD COLUMN.
                    statement = text(
                        f'ALTER TABLE "{table_name}" '
                        f'ADD COLUMN "{column_name}" '
                        f'{column_definition}'
                    )

                    try:

                        with db.engine.begin() as conn:
                            conn.execute(statement)

                        existing_columns.add(
                            column_name
                        )

                        print(
                            f"Added {table_name}.{column_name}"
                        )

                    except Exception as column_error:

                        # If another request/process added it
                        # at the same time, don't crash.
                        error_text = str(
                            column_error
                        ).lower()

                        if (
                            "already exists" in error_text
                            or "duplicate column" in error_text
                        ):
                            print(
                                f"{table_name}.{column_name} "
                                "already exists."
                            )
                            continue

                        raise

            print("Database migration completed.")

            return True

    except Exception as e:

        app.logger.error(
            f"Database migration failed: {e}"
        )

        return False


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():
    """
    Initialize the database.

    IMPORTANT:
    This function is NOT automatically called during module import.
    """

    try:

        with app.app_context():

            print("Initializing database...")

            # Create all tables from models.py
            db.create_all()

            # Check schema
            if not check_database_schema():

                print(
                    "Database schema requires migration."
                )

                if not run_migration():

                    print(
                        "Database migration failed."
                    )

                    return False

            else:

                print(
                    "Database schema is up to date."
                )

            print(
                "Database initialization completed successfully."
            )

            return True

    except Exception as e:

        app.logger.error(
            f"Database initialization error: {e}"
        )

        return False


# ============================================================
# OPTIONAL TABLE FIX FUNCTIONS
# ============================================================
#
# IMPORTANT:
# These functions are NOT automatically executed.
#
# Do NOT automatically DROP tables on Vercel/Neon because
# that would destroy existing data.
#
# They are kept here only if you specifically need them later.
# ============================================================


def fix_direct_messages_table():
    """
    Recreate direct_messages table.

    WARNING:
    This DROPS existing direct_messages data.

    Only run manually if the table is genuinely corrupted.
    """

    try:

        with app.app_context():

            if not is_postgresql():

                print(
                    "This repair function is intended "
                    "for PostgreSQL."
                )

                return False

            with db.engine.begin() as conn:

                conn.execute(
                    text(
                        "DROP TABLE IF EXISTS "
                        "direct_messages CASCADE"
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE TABLE direct_messages (
                            id SERIAL PRIMARY KEY,
                            content TEXT NOT NULL,
                            sender_id INTEGER NOT NULL
                                REFERENCES users(id),
                            recipient_id INTEGER NOT NULL
                                REFERENCES users(id),
                            created_at TIMESTAMP NOT NULL
                                DEFAULT CURRENT_TIMESTAMP,
                            read_at TIMESTAMP,
                            status VARCHAR(20) NOT NULL
                                DEFAULT 'sent',
                            delivered_at TIMESTAMP
                        )
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_dm_conversation
                        ON direct_messages
                        (sender_id, recipient_id, created_at)
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_dm_recipient_unread
                        ON direct_messages
                        (recipient_id, read_at, created_at)
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_dm_user_timeline
                        ON direct_messages
                        (sender_id, created_at)
                        """
                    )
                )

            print(
                "direct_messages table recreated."
            )

            return True

    except Exception as e:

        app.logger.error(
            f"Failed to fix direct_messages: {e}"
        )

        return False


def fix_shared_files_table():
    """
    Recreate shared_files table.

    WARNING:
    This DROPS existing shared_files data.

    Only run manually if the table is genuinely corrupted.
    """

    try:

        with app.app_context():

            if not is_postgresql():

                print(
                    "This repair function is intended "
                    "for PostgreSQL."
                )

                return False

            with db.engine.begin() as conn:

                conn.execute(
                    text(
                        "DROP TABLE IF EXISTS "
                        "shared_files CASCADE"
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE TABLE shared_files (
                            id SERIAL PRIMARY KEY,
                            filename VARCHAR(255) NOT NULL,
                            original_filename VARCHAR(255) NOT NULL,
                            file_data BYTEA,
                            file_path VARCHAR(500),
                            file_size BIGINT NOT NULL,
                            mime_type VARCHAR(100) NOT NULL,
                            uploader_id INTEGER NOT NULL
                                REFERENCES users(id),
                            server_id INTEGER
                                REFERENCES server(id),
                            channel_id INTEGER
                                REFERENCES channel(id),
                            created_at TIMESTAMP NOT NULL
                                DEFAULT CURRENT_TIMESTAMP,
                            is_compressed BOOLEAN
                                DEFAULT FALSE,
                            checksum VARCHAR(64)
                        )
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_file_type_size
                        ON shared_files
                        (mime_type, file_size)
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_server_files
                        ON shared_files
                        (server_id, created_at)
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_channel_files
                        ON shared_files
                        (channel_id, created_at)
                        """
                    )
                )

                conn.execute(
                    text(
                        """
                        CREATE INDEX
                        idx_user_uploads
                        ON shared_files
                        (uploader_id, created_at)
                        """
                    )
                )

            print(
                "shared_files table recreated."
            )

            return True

    except Exception as e:

        app.logger.error(
            f"Failed to fix shared_files: {e}"
        )

        return False


# ============================================================
# IMPORT MODELS
# ============================================================
#
# This must happen BEFORE create_all().
# Otherwise SQLAlchemy may have no model metadata.
# ============================================================

import models  # noqa: E402,F401


# ============================================================
# EXPLICIT DATABASE INITIALIZATION
# ============================================================
#
# DO NOT call init_database() here.
#
# Vercel imports this module when starting the serverless
# function. Running database migrations during import can
# cause deployment/runtime failures.
#
# Call initialize_app_database() manually when you actually
# want to initialize/migrate the database.
# ============================================================


def initialize_app_database():
    """
    Explicitly initialize/migrate the database.

    Returns:
        True  -> success
        False -> failure
    """

    try:

        return init_database()

    except Exception as e:

        app.logger.error(
            f"Database initialization failed: {e}"
        )

        return False


# ============================================================
# HEALTH CHECK
# ============================================================

def database_is_available():
    """
    Test whether the database connection works.
    """

    try:

        with app.app_context():

            with db.engine.connect() as conn:

                conn.execute(
                    text("SELECT 1")
                )

            return True

    except Exception as e:

        app.logger.warning(
            f"Database connection failed: {e}"
        )

        return False
