FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY supervisor.py .
EXPOSE 18012
HEALTHCHECK --interval=5s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18012/health')"
RUN useradd -m supervisor
USER supervisor
CMD ["gunicorn", "-b", "0.0.0.0:18012", "-w", "1", "--threads", "4", "supervisor:app"]
