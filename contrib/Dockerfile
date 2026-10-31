FROM debian:testing-slim as build

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /tmp/build
WORKDIR /tmp/build
COPY . /tmp/build/

RUN apt-get update \
	&& apt-get --no-install-recommends -yqq install \
		# Build dependencies
		build-essential \
		cmake \
		libcurl4-openssl-dev  \
		libfido2-dev \
		libssl-dev  \
		libxml2-dev  \
		pkg-config \
		# Run time dependencies
		libcurl4  \
		libfido2-1 \
		libssl1.1 \
		libxml2 \
		# Optionals handy for testing within the container
		bash-completion \
		ca-certificates \
		xclip \
	&& make \
	&& make test \
	&& make install \
	&& apt-get autoremove --purge -yqq \
		bash-completion \
		libcurl4-openssl-dev  \
		libfido2-dev \
		libssl-dev  \
		libxml2-dev  \
		pkg-config \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/build
