FROM python:3.12-slim

RUN useradd -u 1000 -m sandboxuser

WORKDIR /app/huggingmask_runner

COPY sandbox/b2/entrypoint.py /app/huggingmask_runner/b2_entrypoint.py
COPY sandbox/image/b2/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

USER 1000:1000
ENTRYPOINT ["/usr/bin/env"]
