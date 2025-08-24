FROM python:3.12-slim
RUN apt-get update && apt-get install -y build-essential gcc g++ && rm -rf /var/lib/apt/lists/*
RUN useradd -ms /bin/bash vulnuser
WORKDIR /home/vulnuser/app
COPY --chown=vulnuser:vulnuser . .
RUN pip install --no-cache-dir -r requirements.txt
ENV MODEL_PATH="/home/vulnuser/app/models"
USER vulnuser
ENTRYPOINT ["python", "analyzer.py"]
##final Docker