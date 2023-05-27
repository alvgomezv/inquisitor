#!/bin/bash

docker-compose up -d

docker-compose ps -q | xargs docker inspect --format='{{.State.Status}}' | grep -v 'running' | wc -l | awk '{ if ($1 > 0) exit 1 }'

client_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' client)
client_mac=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' client)
server_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server)
server_mac=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' server)

echo "Client IP: $client_ip"
echo "Client MAC: $client_mac"
echo "Server IP: $server_ip"
echo "Server MAC: $server_mac\n"
echo "python inquisitor.py $client_ip $client_mac $server_ip $server_mac\n"

docker exec -it attacker bash