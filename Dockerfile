FROM debian:bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get -y install \
	gettext autoconf automake libtool autopoint \
	libssl-dev git libbsd-dev build-essential && \
	apt-get clean && rm -rf /tmp/* /var/tmp/*

# Copy everything to /src
RUN mkdir /src
WORKDIR /src
ADD . /src/

# Build
RUN ./autogen.sh --prefix=/build --sysconfdir=/config
RUN make all install

## 
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get -y install gettext \
	libbsd0 openssl man-db && apt-get clean && \
	rm -rf /tmp/* /var/tmp/*

# Copy build artifacts
COPY --from=builder /build/ /usr/
COPY --from=builder /config /config

ENTRYPOINT ["/usr/bin/mactelnet"]