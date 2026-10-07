# Development recipe only: the adapter authorizes the reviewed built image digest,
# not an arbitrary rebuild of this recipe.
FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libxml2 && rm -rf /var/lib/apt/lists/*
ENV LD_LIBRARY_PATH=/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive/lib
ENTRYPOINT ["/evidence/libnvat-linux-sbsa-1.2.2.1780962352-archive/bin/nvattest"]
