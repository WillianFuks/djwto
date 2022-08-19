docker run --rm -it \
  --name docker_quasar \
  -e PGID=1000 -e PUID=1000 \
  -v $(pwd)/../frontend/:/home/alpine/project \
  -v /etc/localtime:/etc/localtime/ro \
  -p 9000:9000 \
  --entrypoint /bin/bash \
  woahbase/alpine-quasar:x86_64 quasar dev -m spa


DOCKER_BUILDKIT=1 docker build -t front_test -f docker/Dockerfile.frontend .
docker run -it --rm --cap-add NET_ADMIN --init -p 9000:9000 -v $(pwd)/frontend:/home/node/app front_test quasar dev

DOCKER_BUILDKIT=1 docker build -t back_test -f docker/Dockerfile.backend .
docker run -it --rm -p 8002:8002 -v $(pwd)/backend:/app/ back_test

docker compose build --build-arg USER_ID="$(id -u)" --build-arg GROUP_ID="$(id -g)"

DOCKER_BUILDKIT=1 docker build -t front_prod -f docker/Dockerfile.frontend_prod .
