#TODO use travis Encrypting environment variables
export FUZZIT_API_KEY=a5bd225de146e4528ee53fc64e713946cb5462fefc31d7c99633ff93899ed0f8b3bdde0beba8a94afb04619064dd8a65

[ -s ./test/fuzz_htp ] || exit 0

if [ "$TRAVIS_EVENT_TYPE" = 'cron' ]; then
    FUZZING_TYPE=fuzzing
else
    FUZZING_TYPE=regression
fi
if [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
    FUZZIT_BRANCH="${TRAVIS_BRANCH}"
else
    FUZZIT_BRANCH="PR-${TRAVIS_PULL_REQUEST}"
fi

FUZZIT_ARGS="--type ${FUZZING_TYPE} --branch ${FUZZIT_BRANCH} --revision ${TRAVIS_COMMIT}"

wget -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v2.4.60/fuzzit_Linux_x86_64
chmod +x fuzzit
set -x
./fuzzit create job ${FUZZIT_ARGS} fuzz-htp-${QA_FUZZIT} ./test/fuzz_htp
set +x
