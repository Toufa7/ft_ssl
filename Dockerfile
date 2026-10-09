FROM ubuntu:latest
RUN apt-get update && apt-get install build-essential -y && apt-get install -y openssl
WORKDIR /FT_SSL
COPY . .
CMD ["bash"]
