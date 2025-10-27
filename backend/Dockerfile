FROM node:20-slim

# Install Python, Wireshark (tshark), FFmpeg, and system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    gcc \
    g++ \
    make \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    libjpeg-dev \
    zlib1g-dev \
    libsndfile1 \
    tshark \
    wireshark-common \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY requirements.txt ./

# Install Node.js dependencies
RUN npm install

# Install Python dependencies system-wide
RUN pip3 install --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Copy Python scripts to a location accessible after build
RUN mkdir -p /app/python-scripts && \
    cp -r src/scripts/pythonScripts/* /app/python-scripts/ || true

# Build TypeScript
RUN npm run build

# Create storage directory
RUN mkdir -p storage/uploads storage/results

# Expose port
EXPOSE 8080

# Start server
CMD ["npm", "start"]
