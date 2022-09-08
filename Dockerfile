FROM alpine:3.16 AS builder

# Install build dependencies
RUN apk add --no-cache diffutils build-base automake autoconf git gettext gettext-dev linux-headers openssl-dev

# Copy everything to /src
RUN mkdir /src
WORKDIR /src
ADD . /src/

# Build
ENV CFLAGS="-D_GNU_SOURCE"
RUN ./autogen.sh --prefix=/build
RUN make all install

## 
FROM alpine:3.16

# Install runtime dependencies
RUN apk add --no-cache gettext-libs openssl-dev

# Copy build artifacts
COPY --from=builder /build/ /usr/

CMD ["/usr/bin/mactelnet"]
