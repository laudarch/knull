# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    masscan \
    nmap \
    wget \
    unzip \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project files into the container
COPY . .

# Make the scripts executable
RUN chmod a+x knull.py knulleye.py tools/count_ips.sh tools/extract_cidr.sh

# Set environment variables for ChromeDriver
ENV CHROME_DRIVER_VERSION=114.0.5735.90
ENV CHROME_DRIVER_PATH=/usr/bin/chromedriver

# Download and install ChromeDriver
RUN wget -q -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/${CHROME_DRIVER_VERSION}/chromedriver_linux64.zip \
    && unzip /tmp/chromedriver.zip -d /usr/bin/ \
    && rm /tmp/chromedriver.zip \
    && chmod +x /usr/bin/chromedriver

# Set the entry point for the container
ENTRYPOINT ["/bin/bash"]