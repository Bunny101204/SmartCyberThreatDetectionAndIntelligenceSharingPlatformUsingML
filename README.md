# ML-Based Cyber Threat Detection and Selective Threat Intelligence Sharing Platform

This project demonstrates a machine learning-powered cyber threat detection system with selective intelligence sharing, inspired by MISP.

## Features
- Multi-model ML threat detection (Random Forest, XGBoost, SVM, Decision Tree)
- Ensemble majority voting for improved accuracy
- Simulated network traffic generation
- FastAPI backend with REST endpoints
- Simple web dashboard for monitoring
- Group-based threat sharing system
- JSON-based storage

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Train models: `cd ml && python train_models.py`
3. Start backend: `cd backend && python main.py`
4. Open frontend: Open `frontend/index.html` in browser, or serve it.

## Deployment in GitHub Codespaces
- The project is designed to run in GitHub Codespaces.
- Use `uvicorn backend.main:app --host 0.0.0.0 --port 8000` to start the server.
- Access the frontend via the provided URL.

## Usage
- Select a laptop ID and start detection to simulate traffic monitoring.
- View live traffic stream and detected threats.
- Share threats to groups for collaborative defense.

## Project Structure
- `ml/`: Machine learning models and prediction logic
- `backend/`: FastAPI server
- `frontend/`: Web dashboard
- `data/`: Dataset storage
- `storage/`: JSON files for threats and groups