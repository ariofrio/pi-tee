FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ARG SOURCE_DATE_EPOCH=0
COPY *.deb /deps/
RUN for package in /deps/*.deb; do dpkg-deb -x "$package" /; done && mkdir -p /etc/ssl/certs && find /usr/share/ca-certificates -type f -name '*.crt' -print0 | sort -z | xargs -0 cat > /etc/ssl/certs/ca-certificates.crt && rm -rf /deps
ENV LD_LIBRARY_PATH=/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive/lib
ENTRYPOINT ["/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive/bin/nvattest"]
