# Setup & Configuration Guide

## Prerequisites
- Python 3.9+
- Docker & Docker Compose (optional, for containerized deployment)
- PhishTank API Key (optional, for enhanced detection)

## 1. Installation

### Local Development
Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/shadow-ops.git
cd shadow-ops
pip install -r requirements.txt
```

### Environment Configuration
Create a `.env` file in the root directory. You can use the provided example:

```bash
copy .env.example .env
```

**Required Variables:**
- `SECRET_KEY`: Random string for session security.
- `JWT_SECRET_KEY`: Random string for API tokens.

**Optional Variables:**
- `PHISHTANK_API_KEY`: Get a free key from [PhishTank](https://www.phishtank.com/api_register.php) to enable real-time URL verification.
- `DATABASE_URL`: Connection string for PostgreSQL (defaults to SQLite for local dev).

## 2. Running the Application

### Using Python (Manual)
To start the Flask development server:

```bash
cd scripts
start.bat
```
*Alternatively, run `python src/app.py` from the root directory.*

The application will be available at `http://localhost:5000`.

### Using Docker (Recommended for Production)
To spin up the entire stack (Web App, Database, Redis):

```bash
docker-compose up -d
```

## 3. API Usage

### Authentication
The API uses JWT authentication. First, obtain a token:

```http
POST /auth/login
Content-Type: application/json

{
    "email": "admin@example.com",
    "password": "your-password"
}
```

### Endpoints

#### `POST /predict`
Analyze a raw text strings for phishing indicators.

**Request:**
```json
{
    "text": "Urgent: Verify your account immediately at http://suspicious-link.tk"
}
```

#### `POST /scan_eml`
Upload a raw `.eml` file for deep forensic analysis.

**form-data:**
- `file`: (Binary `.eml` content)
