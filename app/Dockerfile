

# Use the official Python base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /workspace/flask_app

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install the dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application directory into the container
COPY . .

# Expose the Flask app port
EXPOSE 8080

# Expose the MongoDB port if your application uses MongoDB
EXPOSE 27017


# Start the Gunicorn server
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "wsgi:app"]
