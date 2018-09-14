FROM golang:1.10-stretch
COPY ./build.sh /build.sh
RUN /build.sh