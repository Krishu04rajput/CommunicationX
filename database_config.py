"""
Database configuration for CommunicationX.

This module intentionally does NOT import app.py at module import time.
That avoids circular-import problems when Flask/Vercel loads the application.
"""

import logging
from sqlalchemy import text

logger = logging.getLogger(__name__)


def configure_database_for_large_scale(app, db):
    """
    Optional PostgreSQL tuning.

    Neon/serverless PostgreSQL does not allow many ALTER SYSTEM settings,
    so failures are ignored safely.
    """
    with app.app_context():
        optimization_queries = [
            "ALTER SYSTEM SET checkpoint_completion_target = 0.9",
            "ALTER SYSTEM SET default_statistics_target = 500",
            "ALTER SYSTEM SET random_page_cost = 1.1",
            "ALTER SYSTEM SET wal_compression = on",
            "ALTER SYSTEM SET log_min_duration_statement = 1000",
            "ALTER SYSTEM SET autovacuum_vacuum_scale_factor = 0.1",
            "ALTER SYSTEM SET autovacuum_analyze_scale_factor = 0.05",
        ]

        for query in optimization_queries:
            try:
                db.session.execute(text(query))
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                logger.debug("Database setting skipped: %s", exc)


def create_large_data_tables(app, db):
    """
    Create optional large-scale tables.

    Disabled by default because these are not required for normal
    CommunicationX startup and should not run during every Vercel request.
    """
    return True


def setup_table_compression(app, db):
    """
    Optional compression configuration.

    Disabled for serverless startup.
    """
    return True


def create_performance_monitoring(app, db):
    """
    Optional PostgreSQL monitoring setup.

    Disabled for serverless startup.
    """
    return True


def initialize_database_features(app, db):
    """
    Safe entry point for optional database configuration.

    Nothing here runs automatically when this module is imported.
    """
    try:
        create_large_data_tables(app, db)
        setup_table_compression(app, db)
        create_performance_monitoring(app, db)
        return True
    except Exception as exc:
        logger.warning("Optional database configuration skipped: %s", exc)
        return False


if __name__ == "__main__":
    print(
        "database_config.py is a library module. "
        "Import it from the application instead of running it directly."
    )
