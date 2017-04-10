.PHONY: test

test:
    @bash beacon_test.sh

publish:
    python setup.py sdist bdist_wheel upload

