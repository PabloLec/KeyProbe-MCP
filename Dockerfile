FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libffi-dev \
    rustc \
    cargo \
    curl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
ENV UV_PYTHON=python3.13
ENV UV_LINK_MODE=copy

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --no-dev

COPY keyprobe ./keyprobe
COPY README.md LICENSE ./

RUN uv sync --no-dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["uv", "run", "python", "-m", "keyprobe.server"]