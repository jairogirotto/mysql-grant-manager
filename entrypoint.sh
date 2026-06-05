#!/bin/bash
set -e
python3 -c "from app import init_db; init_db()"
exec gunicorn --workers 2 --bind 0.0.0.0:5050 app:app
