FROM php:8.3-alpine

LABEL authors="roland.rusch@easy-smart.ch"

# Use the default production configuration
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

WORKDIR /var/www/html
EXPOSE 80

ENTRYPOINT ["php", "-S", "0.0.0.0:80"]
#ENTRYPOINT ["ash"]
