# Drubot

AI Drive Thru Ordering System

## Setup (development)

1. Install Rust
2. Install Docker (Docker Desktop)
3. Build + run the backend

    ```shell
    cd backend
    cargo run
    ```

4. Build and run the docker services
    ```shell
    docker compose up --build
    # OR for running in background
    docker compose up --build -d
    # To stop if running in background
    docker compose down -v
    ```

5. Visit the webpages:
    * drubot.localhost (main app page)
    * static.drubot.localhost (static pages, most likely unused but available if we want).
    * pgadmin.drubot.localhost (Postgres Admin UI, development only)

## Docker notes:
* When modifying the Postgres containers (i.e. pgdb and pgadmin) you may have to delete the containers and data for changes to take effect. Delete the containers using Docker Desktop and delete the data in `./containers/data`. Deleting the data will most likely delete and database entires as well.

## TLS/SSL notes:
* When running under local development (i.e. localhost), the SSL certs generated by Caddy are locally signed and will not be trusted by your browser. Thus, you will need to add the locally signed root CA cert to your computers certificate store. SEE: https://caddyserver.com/docs/running#local-https-with-docker

## PGADMIN notes:
* The following describes the setup for pgadmin
    1. Visit pgadmin.drubot.localhost
    2. Login:
        * U: admin@drubot.com
        * P: development
    3. Add a new server:
        * General.Name: pgdb
        * Connection.Host Name/Address: host.docker.internal
        * Connection.Port: 5432
        * Connection.Username: drubot
        * Connection.Password: development
        * Connection.Save Password: yes

## Using PSQL to connect to database from CLI:
* CLI: psql -U drubot -h localhost -p 5432 -d postgres
* Backend Connection String: postgresql://drubot:development@localhost:5432/postgres



## TODO:
* Connect to database in backend
* Add support to database migrations
* Add support for database seed files
