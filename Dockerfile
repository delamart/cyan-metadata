FROM php:7.3-cli

RUN apt-get update && \
    apt-get install -y libgmp3-dev libzip-dev unzip && \
    docker-php-ext-install gmp zip

VOLUME /app
WORKDIR /app

CMD ["php", "-S", "0.0.0.0:8888", "-t", "/app/public"]