FROM public.ecr.aws/lambda/python:3.12 AS build

WORKDIR /opt/build
COPY mcp_server/requirements.txt .
RUN pip install --target /opt/python -r requirements.txt

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_PORT=8080

WORKDIR /app
COPY --from=build /opt/python /usr/local/lib/python3.12/site-packages
COPY mcp_server/server.py /app/server.py

USER 65532:65532
EXPOSE 8080
CMD ["python", "/app/server.py"]
