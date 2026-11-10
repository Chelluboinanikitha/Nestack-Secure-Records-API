
import sqlite3

connection = sqlite3.connect("records.db")

username = input("Enter admin username: ")

cursor = connection.cursor()

cursor.execute(
    "SELECT id FROM users WHERE username = ?",
    (username,)
)

user = cursor.fetchone()

if user:
    cursor.execute(
        "UPDATE users SET role = ? WHERE username = ?",
        ("admin", username)
    )

    connection.commit()
    print("Admin role assigned successfully!")

else:
    print("User not found. Register this user first.")

connection.close()
