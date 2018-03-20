FROM alpine AS builder

# Install build dependencies
RUN apk add --no-cache build-base automake autoconf git gettext gettext-dev linux-headers

# Copy everything to /src
RUN mkdir /src
WORKDIR /src
ADD . /src/

# Build
ENV CFLAGS="-D_GNU_SOURCE" LIBS="-lintl"
RUN ./autogen.sh
RUN ./configure --prefix=/build
RUN make all install

## 
FROM alpine

# Install runtime dependencies
RUN apk add --no-cache gettext-libs

# Copy build artifacts
COPY --from=builder /build/ /usr/

CMD ["/usr/bin/mactelnet"]
