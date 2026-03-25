# Test sequential execution
# @LOCAL
echo "Command 1: Starting"
sleep 0.5
echo "Command 1: Finished"

echo "Command 2: Starting"
sleep 0.5
echo "Command 2: Finished"

echo "Command 3: This is a very long output"
for i in {1..30}; do
    echo "Line $i of output"
done
