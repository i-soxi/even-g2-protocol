#!/bin/bash


mkdir -p pbgenerated/g2 2>/dev/null
rm  -rf pbgenerated/g2/*.py 2>/dev/null

for file in ../../proto/g2_re/*.proto
do
    protoc -I=../../proto/g2_re --python_out=./pbgenerated/g2  ${file} --experimental_allow_proto3_optional 
done
