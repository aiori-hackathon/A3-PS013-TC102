@echo off
REM Start the app after completing the setup steps in README.md.
if not exist .venv\Scripts\activate.bat (
  echo Virtual environment not found. Follow the README setup steps first.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
uvicorn app.main:app --reload
