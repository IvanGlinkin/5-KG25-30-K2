FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    bash \
    dnsutils \
    python3 \
    python3-pip \
    chromium \
    chromium-driver \
    ca-certificates \
    apache2 \
    php \
    libapache2-mod-php \
    php-sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip3 install --no-cache-dir -r /app/requirements.txt --break-system-packages

RUN rm -f /var/www/html/index.html \
    && cp /app/web/index.php /var/www/html/index.php \
    && cp /app/web/.htaccess /var/www/html/.htaccess \
    && ln -s /app/checking_domains /var/www/html/results \
    && mkdir -p /app/checking_domains /tmp/.cache /tmp/.config /tmp/runtime-www-data /tmp/chrome-profile \
    && chmod 700 /tmp/runtime-www-data \
    && chown -R www-data:www-data /app/checking_domains /var/www/html /tmp/.cache /tmp/.config /tmp/runtime-www-data /tmp/chrome-profile

EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]
