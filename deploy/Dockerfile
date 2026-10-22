# syntax=docker/dockerfile:1
# nyctala image: built from the locked dependencies, runs as an unprivileged user.
# Base images are pinned by digest; bump them deliberately.

FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY nyctala ./nyctala
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin nyctala \
 && mkdir /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NYCTALA_DATA=/data
USER 10001:10001
WORKDIR /data
VOLUME /data
EXPOSE 8514
ENTRYPOINT ["nyctala"]
CMD ["serve", "--host", "0.0.0.0"]
