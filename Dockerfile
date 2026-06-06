FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mgm.py .
COPY static/ static/
COPY templates/ templates/
COPY entrypoint.sh .

ENV MGM_DATA_DIR=/data
RUN mkdir -p /data && chmod +x entrypoint.sh

EXPOSE 5050

ENTRYPOINT ["./entrypoint.sh"]
