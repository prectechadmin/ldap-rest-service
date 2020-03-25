FROM python:3.7.6-slim

RUN apt-get update && \
    apt-get install -y \
      gcc \
      python3-dev \
      default-libmysqlclient-dev \
      git \
      wget

# Install Supervisor
RUN apt-get install -y supervisor

COPY supervisord.conf /etc/supervisor/supervisord.conf

# Create user and group
RUN groupadd -g 1000 www && useradd -u 1000 -g www www

RUN mkdir /www && touch /www/docker-volume-not-mounted && chown www:www /www
ADD service /www/
ADD app.py /www/
ADD wsgi.py /www/
COPY requirements.txt /www/
WORKDIR /www

RUN pip install -r /www/requirements.txt
RUN apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev gcc
RUN apt-get autoremove -y

# Supervisor will run gunicorn or celery
CMD ["supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]

EXPOSE 8001