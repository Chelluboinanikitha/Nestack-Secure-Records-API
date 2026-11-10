# Nestack Secure Records API

## Project Overview

The Nestack Secure Records API is a Python Flask-based REST API designed to securely manage user records.

The application provides user registration, login, authentication, session management, and role-based access control.

## Technologies Used

- Python 3.10
- Flask
- SQLite
- bcrypt
- REST API
- Bearer Token Authentication

## Project Structure

```text
Nikitha_Nestack/
│
├── app.py
├── database.py
├── check_password.py
├── create_admin.py
├── records.db
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the project folder

```bash
cd Nikitha_Nestack
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

Windows:

```bash
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
python app.py
```

The API will run at:

`http://127.0.0.1:5000`

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Check API status |
| POST | `/register` | Register a new user |
| POST | `/login` | Login and generate token |
| POST | `/logout` | Logout and revoke token |
| GET | `/records` | Get authenticated user's records |
| POST | `/records` | Create a new record |
| GET | `/records/<record_id>` | Get a single record |
| GET | `/admin/records` | Admin access to all records |

## Authentication

The application uses Bearer Token Authentication.

After successful login, the API generates a secure session token.

Include the token in the Authorization header:

```text
Authorization: Bearer YOUR_SESSION_TOKEN
```

## Security Features

- Password hashing using bcrypt
- Secure session token generation
- SHA-256 hashing of stored session tokens
- Token expiration
- Session revocation during logout
- Brute-force login protection
- Temporary account lockout
- Parameterized SQL queries
- Protected API endpoints
- Role-based admin authorization
- User-specific record access

## Database

SQLite is used to store:

- User information
- Password hashes
- Session tokens (hashed)
- User records
- Account lockout information
- User roles

## Testing

API endpoints can be tested using Postman or another REST API client.

## Author

Chelluboina Nikitha

## License

This project was developed as part of a technical assessment.
