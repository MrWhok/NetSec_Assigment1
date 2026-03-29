# Use a slim version of Python to keep the image small
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Flask typically runs on 5000; make sure this matches your app.run()
EXPOSE 3000

# Set environment variables for Flask
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "mock-ui.py"]