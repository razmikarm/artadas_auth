# Artadas Auth

Authentication server for Artadas project


## Setup Instructions

### Prerequisites

- Python 3.12+
- pip

### Initialization

1. Clone the repository:
   ```bash
   git clone git@github.com:razmikarm/artadas_auth.git
   cd artadas_api
   ```

2. Rename `.env.example` to `.env` and fill real data 

### Local Installation and Run

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Start the server:
   ```bash
   uvicorn app.main:app --reload
   ```

4. Access the API at [127.0.0.1:8000](http://127.0.0.1:8000).

5. View the interactive API docs:
   - Swagger UI: [127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   - ReDoc: [127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)


### Run with Docker

1. Install Docker in your system

2. Install the [Docker Compose](https://docs.docker.com/compose/install/linux/#install-using-the-repository) plugin

3. Build your containers:
   ```bash
   docker compose build
   ```

4. Run containers:
   ```bash
   docker compose up
   ```

5. Access the API at [0.0.0.0:8008](http://0.0.0.0:8008).

6. View the interactive API docs:
   - Swagger UI: [0.0.0.0:8008/docs](http://0.0.0.0:8008/docs)
   - ReDoc: [0.0.0.0:8008/redoc](http://0.0.0.0:8008/redoc)

> The project will be mounted in container, so that container will be up-to-date and will reload on new changes


## Development

### Add pre-commits

1. Install Pre-Commit Hooks:
   ```bash
   pre-commit install
   ```

2. Check if it's working:
   ```bash
   pre-commit run --all-files
   ```

### Check code manually

1. Run to check with linter:
   ```bash
   ruff check
   ```

2. Run to resolve fixable errors:
   ```bash
   ruff check --fix
   ```

3. Run to reformat code:
   ```bash
   ruff format
   ```

### Manage migrations

1. Generate new revision:
   ```bash
   alembic revision --autogenerate -m "Your migration message"
   ```

2. Upgrade Database with new revision:
   ```bash
   alembic upgrade head
   ```

### Clean container dev database

1. Remove existing containers
   ```bash
   docker compose down
   ```

2. Remove database volume
   ```bash
   docker volume rm artadas_api_postgres_data
   ```

3. Or delete volumes with one command:
   ```bash
   docker-compose down -v
   ```


## Testing

1. Install testing dependencies:
   ```bash
   pip install pytest pytest-asyncio
   ```

2. Run tests:
   ```bash
   pytest
   ```

---

### Future Enhancements
- Add authentication using OAuth2 or JWT.
- Integrate Alembic for database migrations.
- Deploy to a cloud provider like AWS, GCP, or Heroku.
