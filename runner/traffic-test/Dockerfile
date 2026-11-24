FROM registry.k8s.io/kubectl:v1.36.4 AS cli
FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iperf3 iproute2 psmisc curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/tft
RUN curl -fsSL --retry 3 https://codeload.github.com/ovn-kubernetes/kubernetes-traffic-flow-tests/tar.gz/9f911a119c7f3008efca1fff9750985810a34603 -o /tmp/tft.tgz && \
    echo '96f2ffe3e1017d4e1a61d047ba9485b6fb99f1fbb92afb88620643e87b3105ce  /tmp/tft.tgz' | sha256sum -c - && \
    tar -xzf /tmp/tft.tgz --strip-components=1 && rm /tmp/tft.tgz && pip install --no-cache-dir -r requirements.txt
COPY --from=cli /bin/kubectl /usr/local/bin/kubectl
RUN ln -s /usr/local/bin/kubectl /usr/local/bin/oc
COPY run.py .
USER 10001:10001
ENTRYPOINT ["python", "/opt/tft/run.py"]
