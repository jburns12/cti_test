#!/bin/bash

curl -s -X POST -H "Content-Type: application/json" \
-H "Accept: application/json" -H "Travis-API-Version: 3" \
-H "Authorization: token ${TRAVIS_TOKEN}" \
-d '{"request":{"branch":"build"}}' \
https://api.travis-ci.com/repo/jburns12%2fjburns12.github.io/requests
