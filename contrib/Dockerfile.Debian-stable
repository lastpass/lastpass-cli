FROM debian:stable-slim as build

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /tmp/build
WORKDIR /tmp/build
COPY . /tmp/build/

RUN apt-get update \
	&& apt-get --no-install-recommends -yqq install \
		# Build dependencies
		build-essential \
		cmake \
		libcurl3-openssl-dev  \
		libssl1.0-dev  \
		libxml2-dev  \
		pkg-config \
		# Run time dependencies
		libcurl3  \
		libssl1.0 \
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
		libcurl3-openssl-dev  \
		libssl1.0-dev  \
		libxml2-dev  \
		pkg-config \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/build
