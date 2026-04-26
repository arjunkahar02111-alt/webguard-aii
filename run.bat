@echo off
echo Starting WebGuard AI Locally...

:: Setup Backend
echo =======================================
echo Setting up Backend...
cd backend
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate.bat
echo Installing backend dependencies...
pip install -r requirements.txt

:: Start Backend in a new terminal
echo Starting FastAPI Backend...
start "WebGuard API" cmd /c "venv\Scripts\activate.bat && uvicorn main:app --reload --port 8000"

:: Return to root
cd ..

:: Setup Frontend
echo =======================================
echo Setting up Frontend...
cd frontend
echo Installing frontend dependencies...
call npm install

:: Start Frontend in a new terminal
echo Starting React Frontend...
start "WebGuard UI" cmd /c "npm run dev"

cd ..
echo =======================================
echo Both services are starting up! Check the new terminal windows.
echo Frontend should be available at http://localhost:3000
echo Backend API docs available at http://localhost:8000/api/docs
pause
