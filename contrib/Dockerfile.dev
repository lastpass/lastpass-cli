FROM debian:testing-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /tmp/build
WORKDIR /tmp/build

RUN apt-get update \
	&& apt-get --no-install-recommends -y install \
		# Build dependencies
		build-essential \
		cmake \
		libcurl4-openssl-dev  \
		libssl-dev  \
		libxml2-dev  \
		pkg-config \
		# Run time dependencies
		libssl1.1 \
		libcurl4  \
		libxml2 \
		# Optionals handy for testing within the container
		bash-completion \
		ca-certificates \
		xclip

COPY . /tmp/build/

RUN make \
	&& make test \
	&& make install
