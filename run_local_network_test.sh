#!/bin/sh

# N f B K
echo "start.sh <N> <F> <B> <K>"

python3 run_trusted_key_gen.py --N $1 --f $2

llall python3
i=0
while [ "$i" -lt $1 ]; do
    echo "start node $i..."
    python3 run_sockets_node.py --sid 'sidB' --id $i --N $1 --f $2 --B $3 --K $4 --S 100 --T 2 --P "dl" --D True --O True &
    i=$(( i + 1 ))
done 
