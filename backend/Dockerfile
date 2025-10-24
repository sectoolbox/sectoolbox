FROM node:20-slim

# Install Python, Wireshark (tshark), and system dependencies
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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY requirements.txt ./

# Install Node.js dependencies
RUN npm install

# Create Python virtual environment and install dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Create storage directory
RUN mkdir -p storage/uploads storage/results

# Expose port
EXPOSE 8080

# Start server
CMD ["npm", "start"]
