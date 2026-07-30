FROM golang:1.25-bookworm AS sf
RUN go install github.com/richardlehane/siegfried/cmd/sf@latest

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends file git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=sf /go/bin/sf /usr/local/bin/sf
RUN sf -update

WORKDIR /work

COPY requirements.txt identify_harnesses.py ./

RUN pip install --no-cache-dir -r requirements.txt \
    && git clone --depth 1 https://github.com/google/oss-fuzz.git

ENTRYPOINT ["python3", "identify_harnesses.py"]
