#!/bin/bash

curl -s -X POST -H "Content-Type: application/json" \
-H "Accept: application/json" -H "Travis-API-Version: 3" \
-H "Authorization: token ${TRAVIS_TOKEN}" \
-d '{"request":{"branch":"master"}}' \
https://api.travis-ci.com/repo/jburns12%2fweb_test/requests
