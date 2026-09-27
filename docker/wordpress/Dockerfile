# Laboratorio Elementor CSRF — imagen WordPress parametrizada.
#
# El componente vulnerable NO es el core de WordPress sino el plugin Elementor,
# por eso víctima y control comparten la MISMA imagen base (variable única del
# experimento: la versión de Elementor, 4.3.1 vulnerable vs 4.3.2 parcheada).
#
# WP 7.1 = "Tested up to" declarado por Elementor 4.3.x.

ARG WP_IMAGE=wordpress:7.1-php8.3-apache
FROM ${WP_IMAGE}

# Versión de Elementor que se inyectará en el lab (4.3.1 víctima / 4.3.2 control).
ARG ELEMENTOR_VERSION=4.3.1
ENV ELEMENTOR_VERSION=${ELEMENTOR_VERSION}

# unzip: para desempaquetar el zip de Elementor en la imagen.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*

# WP-CLI: aprovisionamiento idempotente en el arranque.
ADD https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar /usr/local/bin/wp
RUN chmod +x /usr/local/bin/wp

# Elementor pinneado por versión desde wordpress.org (canal oficial del plugin).
# El módulo vulnerable vive en:
#   core/common/modules/events-manager/rest-api/events-proxy-rest-api.php
# En 4.3.0 y 4.3.1 el archivo es byte a byte idéntico (verificado en research/).
RUN curl -fsSL -o /tmp/elementor.zip \
        "https://downloads.wordpress.org/plugin/elementor.${ELEMENTOR_VERSION}.zip" \
    && unzip -q /tmp/elementor.zip -d /usr/src/elementor-dist \
    && rm -f /tmp/elementor.zip

COPY entrypoint.sh /usr/local/bin/lab-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-entrypoint.sh

ENTRYPOINT ["lab-entrypoint.sh"]
CMD ["apache2-foreground"]
