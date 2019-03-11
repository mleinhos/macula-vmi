#!/bin/bash
FILES=/home/saqib/random_sample/*
i=1
index=23
for f in $FILES
do
 genisoimage -o "/home/saqib/final_iso/sample_$i.iso" $f
 let i=i+1
done
