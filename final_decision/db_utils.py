import sqlite3
import time
DEFAULT_TIMEOUT = 10
DEFAULT_BUSY_TIMEOUT = 5000
def get_connection(db_path,retries=5,delay=0.10):
    last_error = None
    for attempt in range(retries):
        try:
            conn = sqlite3.connect(db_path,timeout=DEFAULT_TIMEOUT)
            conn.execute(f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT}")
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except sqlite3.OperationalError as error:
            last_error = error
            if attempt >= retries - 1:
                raise
            time.sleep(
                delay * (attempt + 1)
            )

    raise last_error