from psycopg2 import connect, connection, extras

host = "localhost"
port = 5432
db_name = "twitter-back"
username = 'postgres'
password = "rafael"


def get_connection():
    connection = connect(host=host, port=port, dbname=db_name,
                         user=username, password=password)
    return connection


def get_cursor_dict():
    connection = get_connection()
    return connection.cursor(cursor_factory=extras.DictCursor)
