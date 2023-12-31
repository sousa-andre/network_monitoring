import os
import statistics
import time
from locust import HttpUser, task, between
import datetime as dt
import datetime
import psycopg2
from psycopg2 import sql

LOOKUP_DATE_RANGE = '2023-07-10 12:00:00', '2023-07-29 14:00:00'


def get_connection_func():
    connection = psycopg2.connect(
        host=os.getenv('DATABASE_HOST'),
        port=os.getenv('DATABASE_PORT'),
        dbname=os.getenv('DATABASE_DBNAME'),
        user=os.getenv('DATABASE_USER'),
        password=os.getenv('DATABASE_PASSWORD')
    )

    def connection_inner():
        return connection

    return connection_inner


get_connection = get_connection_func()


class MyUser(HttpUser):
    user_count = 0
    total_users = 0
    aggregated_data = {}
    response_time_data = {}
    wait_time = between(1, 3)

    @staticmethod
    def get_current_time():
        now = datetime.datetime.now()
        return now

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rps_data = []
        self.time_data = []
        self.db_connection = None

        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS locustData (
                        id SERIAL PRIMARY KEY,
                        url VARCHAR(255),
                        date TIMESTAMP,
                        timestamp INTEGER,
                        request_count INTEGER,
                        failure_count INTEGER,
                        avg_response_time INTEGER, 
                        min_response_time INTEGER, 
                        max_response_time INTEGER, 
                        median_response_time FLOAT
                    )
                """)
            connection.commit()

    def on_start(self):
        self.rps_data = []
        self.time_data = []
        MyUser.total_users = MyUser.total_users + 1

        self.db_connection = get_connection()

    def on_stop(self):
        MyUser.user_count += 1

        with self.db_connection.cursor() as cursor:
            for request_name, data in MyUser.response_time_data.items():
                if request_name not in MyUser.aggregated_data:
                    MyUser.aggregated_data[request_name] = {
                        "request_count": 0,
                        "failure_count": 0,
                        "response_times": []
                    }

                MyUser.aggregated_data[request_name]["request_count"] += data["request_count"]
                MyUser.aggregated_data[request_name]["failure_count"] += self.environment.stats.entries.get(
                    request_name, {}).get("fail", 0)
                MyUser.aggregated_data[request_name]["response_times"].extend(data["response_time"])
            if MyUser.user_count == MyUser.total_users:
                for request_name, data in MyUser.aggregated_data.items():
                    url = request_name
                    request_count = data["request_count"]
                    failure_count = data["failure_count"]
                    response_times = data["response_times"]
                    avg_response_time = sum(response_times) / len(response_times)
                    min_response_time = min(response_times)
                    max_response_time = max(response_times)
                    median_response_time = statistics.median(response_times)
                    date_obj = dt.datetime.strptime(self.get_current_time(), '%Y-%m-%d %H:%M:%S')
                    unix_timestamp = int(date_obj.timestamp())

                    query = sql.SQL("""
                            INSERT INTO locustData (url, date, timestamp, request_count, failure_count, avg_response_time, min_response_time, max_response_time, median_response_time)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """)

                    cursor.execute(query, (
                        url, unix_timestamp, self.get_current_time(), request_count, failure_count, avg_response_time,
                        min_response_time, max_response_time, median_response_time))

        self.db_connection.commit()
        # self.db_connection.close()

    @task
    def test_api(self):
        conn = get_connection()
        cur = conn.cursor()

        first_date, second_date = LOOKUP_DATE_RANGE
        first_date1 = dt.datetime.strptime(first_date, "%Y-%m-%d %H:%M:%S")
        second_date2 = dt.datetime.strptime(second_date, "%Y-%m-%d %H:%M:%S")
        first_date_timestamp = time.mktime(first_date1.timetuple())
        second_date_timestamp = time.mktime(second_date2.timetuple())

        query = sql.SQL("SELECT method, path, body FROM requests  where timestamp_seconds BETWEEN %s AND %s")
        cur.execute(query, (first_date_timestamp, second_date_timestamp))

        rows = cur.fetchall()

        for row in rows:
            method, path, body = row

            response = self.client.request(method, path, data=body)

            self.add_request_data(path, response.elapsed.total_seconds())
        cur.close()
        # conn.close()

    def add_request_data(self, request_name, elapsed_time):
        self.rps_data.append(1)
        self.time_data.append(self.get_current_time())

        if request_name not in MyUser.response_time_data:
            MyUser.response_time_data[request_name] = {
                "date": [],
                "response_time": [],
                "request_count": 0,
                "failure_count": 0
            }

        MyUser.response_time_data[request_name]["date"].append(self.get_current_time())
        MyUser.response_time_data[request_name]["response_time"].append(elapsed_time)
        MyUser.response_time_data[request_name]["request_count"] += 1


if __name__ == "__main__":
    my_user = MyUser()
    my_user.run()
