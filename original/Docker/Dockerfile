# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required by Playwright browsers
# This step is crucial and might need adjustments based on the base image and browsers installed
# The `playwright install --with-deps` command attempts to install these.
# If it fails, you may need to add them manually here (e.g., for Chromium on Debian/Ubuntu):
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
#     libcups2 libdrm2 libgbm1 libasound2 libpango-1.0-0 \
#     libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 \
#     libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxtst6 \
#     ca-certificates fonts-liberation libappindicator3-1 libxss1 \
#     lsb-release xdg-utils wget \
#     && rm -rf /var/lib/apt/lists/*

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Using --no-cache-dir to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium in this case)
# The `--with-deps` flag tries to install necessary OS dependencies for the browsers.
RUN python -m playwright install --with-deps chromium
# If you want other browsers:
# RUN python -m playwright install firefox
# RUN python -m playwright install webkit

# Copy the rest of the application code to the working directory
COPY app.py .

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable for proxy (optional, can be set at `docker run`)
# ENV PROXY_SERVER="http://your_default_proxy_ip:port"

# Run app.py when the container launches using Gunicorn
# For development, you could use: CMD ["flask", "run", "--host=0.0.0.0"]
# Gunicorn is more production-ready
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--worker-class", "sync", "app:app"]
# For async with uvicorn and an async framework (like FastAPI/Quart), you'd use something different