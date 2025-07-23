FROM python:3.9

WORKDIR /app


RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*


RUN wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz \
    && rm go1.21.0.linux-amd64.tar.gz
ENV PATH=/usr/local/go/bin:$PATH
ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:$PATH


RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN git clone https://github.com/HuntDownProject/HEDnsExtractor.git /tmp/HEDnsExtractor \
    && cd /tmp/HEDnsExtractor \
    && make \
    && cp hednsextractor /usr/local/bin/ \
    && chmod +x /usr/local/bin/hednsextractor \
    && rm -rf /tmp/HEDnsExtractor


COPY . .


RUN pip install --no-cache-dir werkzeug==2.2.3 \
    && pip install --no-cache-dir dnspython==2.0.0 \
    && pip install --no-cache-dir flask==2.2.3 \
    flask-cors==3.0.10 \
    python-whois==0.8.0 \
    ipwhois==1.2.0 \
    urllib3==1.26.15 \
    geoip2==4.6.0 \
    pyOpenSSL==23.1.1 \
    requests==2.28.2


EXPOSE 5000


CMD ["python", "app.py"]