FROM node:20-slim

# Install Python and system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libpcap-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY requirements.txt ./

# Install Node.js dependencies
RUN npm install

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

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
