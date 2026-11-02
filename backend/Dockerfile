FROM python:3.14.0-slim-bookworm

WORKDIR /app

ARG TSHARK_VERSION=4.0.17-0+deb12u3
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        tshark=${TSHARK_VERSION} \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock ./
RUN pip install --no-cache-dir --requirement requirements.lock

COPY pyproject.toml ./
COPY app ./app
COPY tests ./tests

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
