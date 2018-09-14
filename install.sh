#!/bin/bash

set -e

if (command -v docker)
then
  echo '[i] Using docker to build the things'
  { docker kill vuls-complete; } || { echo ''; }

  docker build -t vuls-complete .

  readonly container_id=$(docker run --rm --name vuls-complete -d vuls-complete sleep 10)

  binaries=(goval-dictionary vuls go-cve-dictionary)

  for binary in ${binaries[@]}
  do
    docker cp "${container_id}:/go/bin/${binary}" "./bin/${binary}"
  done
  exit 0
fi

if (command -v go)
then
  ./build.sh
  exit 0
fi

echo '[!] You need docker or golang + make + git installed'
exit 1