FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py .
EXPOSE 18010
HEALTHCHECK --interval=5s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18010/health')"
RUN useradd -m colony
USER colony
CMD ["gunicorn", "-b", "0.0.0.0:18010", "-w", "1", "--threads", "8", "app:app"]
