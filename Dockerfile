FROM python:3.7.6-slim

ENV LDAP_URI 'ldaps://ldap01.rdng.uk.cloudxtiny.com'
ENV LDAP_BINDDN "cn=Manager,dc=cloudxtiny,dc=com"
ENV LDAP_SECRET "pr3t3chld4p4dm1n"
ENV LDAP_AUTH_BASEDN  "ou=People,ou=clickitcloud,dc=cloudxtiny,dc=com"
ENV LDAP_AUTH_GROUP_BASEDN  "ou=Group,ou=clickitcloud,dc=cloudxtiny,dc=com"
ENV ENCRYPT_KEY "3223232323"
ENV AUTH_TOKEN  "dlkfd-lfkd"
ENV OVIRT_ENGINE_URL = "https://ovirt-mngnt01.rdng.uk.cloudxtiny.com/ovirt-engine"
ENV SQLALCHEMY_DATABASE_URI  "mysql+pymysql://user:pass@hostname/database"
ENV OVIRT_ADMIN_USER "user"
ENV OVIRT_ADMIN_PASSWORD "password"
ENV OVIRT_CERT_PATH ""
ENV API_SECRET_KEY ""

RUN apt-get update && \
    apt-get install -y \
      gcc \
      python3-dev \
      default-libmysqlclient-dev \
      git \
      wget

RUN apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev
RUN apt-get autoremove -y

# Install Supervisor
RUN apt-get install -y supervisor

COPY supervisord.conf /etc/supervisor/supervisord.conf

# Create user and group
RUN groupadd -g 1000 www && useradd -u 1000 -g www www

RUN mkdir /www && touch /www/docker-volume-not-mounted && chown www:www /www
ADD service /www/service
ADD domain /www/domain
ADD app.py /www/
ADD config.py /www/
ADD wsgi.py /www/
COPY requirements.txt /www/
WORKDIR /www

RUN pip3 install -r /www/requirements.txt

# Supervisor will run gunicorn or celery
CMD ["supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]

EXPOSE 8001