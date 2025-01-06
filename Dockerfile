# Use official Python image from the Docker Hub
FROM python:3.12-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements.txt first
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port FastAPI runs on (default is 8000)
EXPOSE 8000

# Command to run the FastAPI application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
