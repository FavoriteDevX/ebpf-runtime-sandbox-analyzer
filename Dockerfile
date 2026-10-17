# Use a minimal, secure Linux base image
FROM python:3.11-slim

# Set system execution constraints
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy project architecture blueprints
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sandbox.py .

# Run the analyzer under a non-privileged system user for zero-trust isolation
RUN useradd -u 8888 sandboxuser && chown -R sandboxuser:sandboxuser /app
USER sandboxuser

# Trigger execution analytics pipeline
CMD ["python", "sandbox.py"]
