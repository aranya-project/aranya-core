#!/bin/bash
count=0
while [ $count -lt 50 ]; do
    count=$((count + 1))
    echo "Run $count"
    TMPDIR=/dev/shm DUMP_GENERATED_RULES="failing_$count.test" timeout 10 cargo test -p aranya-runtime storage::linear::test::generate_graph 2>&1
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "TIMEOUT at run $count - saved to failing_$count.test"
        ls -la crates/aranya-runtime/src/testing/testdata/failing_$count.test
        break
    elif [ $exit_code -ne 0 ]; then
        echo "FAILED at run $count - saved to failing_$count.test"
        ls -la crates/aranya-runtime/src/testing/testdata/failing_$count.test
        break
    else
        rm -f crates/aranya-runtime/src/testing/testdata/failing_$count.test 2>/dev/null
    fi
done
