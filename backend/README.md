# Sectoolbox Backend

Backend API for Sectoolbox forensics platform.

## Features

- Python script execution with full library support
- PCAP analysis (Wireshark-grade with Scapy)
- Audio processing (FFT, spectrograms)
- Job queue with Redis + Bull
- WebSocket real-time updates
- Auto-cleanup after 1 hour

## Deployment

Automatically deploys to Railway when pushed to GitHub.

## Environment Variables

Set in Railway dashboard - see `.env.example`.
