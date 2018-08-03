#!/usr/bin/env bash
mkdir -p html
rm html/*
source ~/venv/27/bin/activate
nosetests --with-coverage --cover-erase --cover-package=oss2 unittests
mv .coverage .coverage1
nosetests --with-coverage --cover-erase --cover-package=oss2 tests
mv .coverage .coverage2
source ~/venv/36/bin/activate
nosetests --with-coverage --cover-erase --cover-package=oss2 unittests
mv .coverage .coverage3
nosetests --with-coverage --cover-erase --cover-package=oss2 tests
mv .coverage .coverage4
coverage combine .coverage1 .coverage2 .coverage3 .coverage4
coverage html --directory=./html
