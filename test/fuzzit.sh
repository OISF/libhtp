[ -s ./test/fuzz_htp ] || exit 0

if [ "$TRAVIS_EVENT_TYPE" = 'cron' ]; then
    FUZZING_TYPE=fuzzing
else
    FUZZING_TYPE=local-regression
fi
if [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
    FUZZIT_BRANCH="${TRAVIS_BRANCH}"
else
    FUZZIT_BRANCH="PR-${TRAVIS_PULL_REQUEST}"
fi

FUZZIT_ARGS="--type ${FUZZING_TYPE} --branch ${FUZZIT_BRANCH} --revision ${TRAVIS_COMMIT}"

wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/latest/download/fuzzit_Linux_x86_64
chmod +x fuzzit
set -x
./fuzzit create job ${FUZZIT_ARGS} oisf-gh/fuzz-htp-${QA_FUZZIT} ./test/fuzz_htp
set +x
