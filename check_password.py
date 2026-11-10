
import sqlite3

connection = sqlite3.connect("records.db")

users = connection.execute(
    "SELECT username, password_hash FROM users"
).fetchall()

for user in users:
    print("Username:", user[0])
    print("Password hash:", user[1])
    print("----------------------")

connection.close()
