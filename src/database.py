import sqlite3
import os
from datetime import datetime


def get_database_path():
    """
    Return the absolute path of the SQLite database.
    """

    current_dir = os.path.dirname(os.path.abspath(__file__))

    database_path = os.path.join(
        current_dir,
        "..",
        "data",
        "insider_threat.db"
    )

    return database_path


def initialize_database():
    """
    Create the database and threat history table
    if they do not already exist.
    """

    database_path = get_database_path()

    connection = sqlite3.connect(database_path)

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_time TEXT,
            username TEXT,
            threat TEXT,
            risk_score INTEGER
        )
        """
    )

    connection.commit()
    connection.close()


def save_analysis(threats, risks):
    """
    Save detected threats and risk scores
    into the SQLite database.
    """

    initialize_database()

    database_path = get_database_path()

    connection = sqlite3.connect(database_path)

    cursor = connection.cursor()

    analysis_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for user, issues in threats.items():

        risk_score = risks.get(user, 0)

        for issue in issues:

            cursor.execute(
                """
                INSERT INTO threat_history
                (
                    analysis_time,
                    username,
                    threat,
                    risk_score
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    analysis_time,
                    user,
                    issue,
                    risk_score
                )
            )

    connection.commit()
    connection.close()


def get_threat_history():
    """
    Retrieve all stored threat records.
    """

    initialize_database()

    database_path = get_database_path()

    connection = sqlite3.connect(database_path)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            analysis_time,
            username,
            threat,
            risk_score
        FROM threat_history
        ORDER BY id DESC
        """
    )

    records = cursor.fetchall()

    connection.close()

    return records


if __name__ == "__main__":

    initialize_database()

    print("Database initialized successfully.")

    print("Database path:")

    print(get_database_path())
