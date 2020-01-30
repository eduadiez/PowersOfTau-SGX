FROM alpine:latest

WORKDIR /app

RUN apk add -U python git py-pip && \
    pip install pyelftools && \
    git clone https://github.com/kudelskisecurity/sgxfun /app

CMD ["./parse_quote.py", "quote.bin"]