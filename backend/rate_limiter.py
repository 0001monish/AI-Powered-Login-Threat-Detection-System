from datetime import datetime, timedelta
from database import cursor, conn

MAX_REQUESTS = 5

WINDOW_MINUTES = 1

def check_rate_limit(ip):

    cursor.execute(
        """
        SELECT request_count, window_start
        FROM ip_rate_limits
        WHERE ip_address=%s
        """,
        (ip,)
    )

    record = cursor.fetchone()

    if not record:

        cursor.execute(
            """
            INSERT INTO ip_rate_limits
            (
                ip_address,
                request_count,
                window_start
            )
            VALUES (%s, %s, %s)
            """,
            (
                ip,
                1,
                datetime.now()
            )
        )

        conn.commit()

        return True

    count = record[0]
    start_time = record[1]

    if datetime.now() > start_time + timedelta(minutes=WINDOW_MINUTES):

        cursor.execute(
            """
            UPDATE ip_rate_limits
            SET
                request_count=1,
                window_start=%s
            WHERE ip_address=%s
            """,
            (
                datetime.now(),
                ip
            )
        )

        conn.commit()

        return True

    if count >= MAX_REQUESTS:
        return False

    cursor.execute(
        """
        UPDATE ip_rate_limits
        SET request_count=request_count + 1
        WHERE ip_address=%s
        """,
        (ip,)
    )

    conn.commit()

    return True