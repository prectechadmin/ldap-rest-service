FROM python:3.7.6-slim


RUN apt-get update && \
    apt-get install -y \
      gcc \
      python3-dev \
      default-libmysqlclient-dev \
      git \
      libxml2 \
      libxml2-dev \
      wget \
      vim

RUN apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev libcurl4-gnutls-dev
RUN apt-get autoremove -y

# Install Supervisor
RUN apt-get install -y supervisor

COPY supervisord.conf /etc/supervisor/supervisord.conf

# Create user and group
RUN groupadd -g 1000 www && useradd -u 1000 -g www www

RUN mkdir /www && touch /www/docker-volume-not-mounted && chown www:www /www
ADD ovirt-ca.cer /www/
ADD service /www/service
ADD lib /www/lib
ADD domain /www/domain
ADD app.py /www/
ADD api_setup.py /www/
ADD config.py /www/
ADD wsgi.py /www/
COPY requirements.txt /www/
WORKDIR /www

RUN pip3 install -r /www/requirements.txt

# Supervisor will run gunicorn or celery
CMD ["supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]

EXPOSE 8001