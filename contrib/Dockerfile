FROM debian:testing-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /tmp/build
WORKDIR /tmp/build
COPY . /tmp/build/

RUN apt-get update \
	&& apt-get --no-install-recommends -yqq install \
		bash-completion \
		build-essential \
		cmake \
		libcurl3  \
		libcurl4-openssl-dev  \
		# We install libssl1.0-dev because.. warnings otherwise
		#libssl-dev  \
		libssl1.0-dev \
		libxml2  \
		libxml2-dev  \
		openssl  \
		pkg-config \
		ca-certificates \
		xclip \
	&& make \
	&& make test \
	&& make install \
	&& apt-get autoremove --purge -yqq \
		bash-completion \
		libcurl4-openssl-dev  \
		libssl1.0-dev \
		#libssl-dev  \
		libxml2-dev  \
		pkg-config \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/build
