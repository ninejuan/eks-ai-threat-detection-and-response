FROM public.ecr.aws/lambda/python:3.12 AS build

WORKDIR /opt/build
COPY mcp_server/requirements.txt .
RUN pip install --target /opt/python -r requirements.txt

COPY mcp_server/proto /opt/build/proto
RUN PYTHONPATH=/opt/python python -m grpc_tools.protoc \
        -I /opt/build/proto \
        --python_out=/opt/generated \
        --grpc_python_out=/opt/generated \
        /opt/build/proto/flow/flow.proto \
        /opt/build/proto/relay/relay.proto \
        /opt/build/proto/observer/observer.proto \
    && find /opt/generated -type d -exec touch {}/__init__.py \;

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_PORT=8080

WORKDIR /app
COPY --from=build /opt/python /usr/local/lib/python3.12/site-packages
COPY --from=build /opt/generated /app/_generated
COPY mcp_server/server.py /app/server.py
COPY mcp_server/hubble_client.py /app/hubble_client.py

ENV PYTHONPATH=/app/_generated

USER 65532:65532
EXPOSE 8080
CMD ["python", "/app/server.py"]
