#!/usr/bin/env bash
# Merge AFL++ queue back into libFuzzer corpus

for target in request hpack ws h2_frame; do
    QUEUE="fuzz/findings/${target}/master/queue"
    CORPUS="fuzz/corpus/${target}"

    if [ -d "$QUEUE" ]; then
        echo "Syncing $target corpus..."
        cp "$QUEUE"/id:* "$CORPUS"/ 2>/dev/null || true

        # Minimize corpus
        echo "Minimizing $target corpus..."
        afl-cmin -i "$CORPUS" -o "${CORPUS}_min" \
                 -- "build_afl/fuzz/afl_fuzz_${target}" 2>/dev/null || true

        if [ -d "${CORPUS}_min" ]; then
            rm -rf "$CORPUS"
            mv "${CORPUS}_min" "$CORPUS"
            echo "Synced $target: $(ls "$CORPUS" | wc -l) test cases"
        fi
    else
        echo "No findings for $target yet"
    fi
done

echo "Corpus sync complete"
