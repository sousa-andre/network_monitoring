import os
import statistics
import time
from locust import HttpUser, task, between
import datetime as dt
import datetime
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

load_dotenv()


class MyUser(HttpUser):
    user_count = 0
    total_users = 0
    aggregated_data = {}
    wait_time = between(1, 3)

    @staticmethod
    def get_current_time():
        now = datetime.datetime.now()
        return now

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rps_data = []
        self.time_data = []
        self.response_time_data = {}
        self.db_connection = None

        with self.get_db_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS locustData (
                        id SERIAL PRIMARY KEY,
                        url VARCHAR(255),
                        timestamp TIMESTAMP,
                        request_count INTEGER,
                        failure_count INTEGER,
                        avg_response_time INTEGER, 
                        min_response_time INTEGER, 
                        max_response_time INTEGER, 
                        median_response_time FLOAT
                    )
                """)
            connection.commit()

    @staticmethod
    def get_db_connection():
        return psycopg2.connect(
            host='db',
            #port=os.getenv('DATABASE_PORT'),
            dbname='postgres',
            user='postgres',
            password='postgres'
        )

    def on_start(self):
        self.rps_data = []
        self.time_data = []
        self.response_time_data = {}
        MyUser.total_users = MyUser.total_users + 1

        self.db_connection = self.get_db_connection()

    def on_stop(self):
        MyUser.user_count += 1

        with self.db_connection.cursor() as cursor:
            for request_name, data in self.response_time_data.items():
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

                    query = sql.SQL("""
                            INSERT INTO locustData (
                            url, 
                            timestamp, 
                            request_count, 
                            failure_count, 
                            avg_response_time, 
                            min_response_time, 
                            max_response_time, 
                            median_response_time
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """)

                    cursor.execute(query, (
                        url, self.get_current_time(), request_count, failure_count, avg_response_time,
                        min_response_time,
                        max_response_time, median_response_time))

        self.db_connection.commit()
        self.db_connection.close()

    @task
    def test_api(self):
        conn = self.get_db_connection()

        cur = conn.cursor()

        first_date = os.getenv("FIRST_DATE")
        second_date = os.getenv("SECOND_DATE")
        first_date1 = dt.datetime.strptime(first_date, "%Y-%m-%d %H:%M:%S")
        second_date2 = dt.datetime.strptime(second_date, "%Y-%m-%d %H:%M:%S")
        first_date_timestamp = time.mktime(first_date1.timetuple())
        second_date_timestamp = time.mktime(second_date2.timetuple())

        query = sql.SQL("SELECT method, path, body FROM requests where timestamp_seconds BETWEEN %s AND %s")
        cur.execute(query, (first_date_timestamp, second_date_timestamp))

        rows = cur.fetchall()

        for row in rows:
            method, path, body = row

            response = self.client.request(method, path, data=body)

            self.add_request_data(path, response.elapsed.total_seconds())
        cur.close()
        conn.close()

    def add_request_data(self, request_name, elapsed_time):
        self.rps_data.append(1)
        self.time_data.append(self.get_current_time())

        if request_name not in self.response_time_data:
            self.response_time_data[request_name] = {
                "timestamps": [],
                "response_time": [],
                "request_count": 0,
                "failure_count": 0
            }

        self.response_time_data[request_name]["timestamps"].append(self.get_current_time())
        self.response_time_data[request_name]["response_time"].append(elapsed_time)
        self.response_time_data[request_name]["request_count"] += 1


if __name__ == "__main__":
    my_user = MyUser()
    my_user.run()
