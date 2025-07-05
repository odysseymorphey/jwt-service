FROM postgres:15.3-alpine

COPY ./migrations/init.sql /docker-entrypoint-initdb.d/

RUN chmod +x /docker-entrypoint-initdb.d/init.sql

ENV POSTGRES_USER=postgres \
    POSTGRES_PASSWORD=mysecretpassword \
    POSTGRES_DB=postgres