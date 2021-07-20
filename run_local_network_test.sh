#!/bin/sh

# N f B K
echo "start.sh <N> <F> <B> <K>"

python3 run_trusted_key_gen.py --N $1 --f $2

llall python3
i=0
while [ "$i" -lt $1 ]; do
    echo "start node $i..."
    python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --f $2 --B $3 --K $4 --S 500 --T 2 --P "xd" --D True --O True &
    i=$(( i + 1 ))
done 
