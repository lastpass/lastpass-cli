# docker build -f contrib/Dockerfile [--build-arg BASE=debian:stable-slim] .
ARG BASE=debian:testing-slim

FROM ${BASE} AS build

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /tmp/build

RUN apt-get update \
	&& apt-get --no-install-recommends -yqq install \
		# Build dependencies, they pull in the matching run time libraries
		build-essential \
		cmake \
		libcurl4-openssl-dev \
		libfido2-dev \
		libssl-dev \
		libxml2-dev \
		pkg-config \
		bash-completion

COPY . .

# Install into /out and list the packages providing the libraries lpass links against
RUN make \
	&& make test \
	&& make install DESTDIR=/out \
	&& libs="$(ldd /out/usr/bin/lpass)" \
	&& ! grep -q 'not found' <<< "$libs" \
	&& awk '/=>/ { so = $(NF-1); sub("^/(usr/)?", "", so); print "*" so }' <<< "$libs" \
		| sort -u \
		| xargs dpkg-query --search \
		| sed -n 's/^\([^: ]*\)\(:[^ :]*\)\{0,1\}: \/.*/\1/p' \
		| sort -u > /runtime-pkgs \
	&& test -s /runtime-pkgs

FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive

COPY --from=build /runtime-pkgs /tmp/runtime-pkgs
COPY --from=build /out/ /

RUN apt-get update \
	&& apt-get --no-install-recommends -yqq install \
		ca-certificates \
		xclip \
		$(cat /tmp/runtime-pkgs) \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/runtime-pkgs \
	&& lpass --version
