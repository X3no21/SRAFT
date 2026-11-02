#!/bin/bash

docker stop pg_server
docker rm pg_server
docker volume rm pg_data_fresh