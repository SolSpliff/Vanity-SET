\
    @echo off
    python -m venv .venv
    .venv\\Scripts\\activate
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    echo Dependencies installed. Activate the venv with: .venv\Scripts\activate
    pause
