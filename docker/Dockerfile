# Test image for polyswarm-api: the whole repo + the test suite, run against a
# live e2e stack. Built by CI (.build-docker) as ${REGISTRY_URL}/polyswarm-api
# and invoked by the e2e `polyswarm-api` command (see the e2e repo) which runs
# the suite VCR-off against the running stack. Not a deployable artifact.
FROM public.ecr.aws/docker/library/python:3.12-slim-bookworm

WORKDIR /usr/src/app

ARG PIP_INDEX_URL="https://pypi.python.org/simple"
ARG UV_INDEX_URL

# Whole repo (src + test/ incl. fixtures + cassettes). .dockerignore keeps local
# cruft (.venv, .git, caches) out.
COPY . .

RUN pip install --no-cache-dir .[tests]

# Default to a live run against the stack: VCR bypassed (no replay/record). The
# tests target the e2e service DNS names (artifact-index-e2e:9696,
# sandbox-service-e2e:54110) which resolve on the e2e network. The e2e command
# also sets these explicitly.
ENV TESTS_VCR=off
ENV TESTS_LOG_LEVEL=INFO
# Unbuffered stdout/stderr so per-test results and the suite's INFO poll lines
# appear live (the harness streams this command), not in one dump at the end.
ENV PYTHONUNBUFFERED=1

# --timeout is a backstop for the live run: VCR-off keeps real poll/sleep pacing,
# so a non-terminating test (e.g. a pagination loop) would otherwise hang until the
# CI job limit. The signal method does NOT reliably interrupt a hang inside the
# asyncio event loop, so use --timeout-method=thread: a watchdog thread fires
# regardless of event-loop state, dumps every thread's stack (showing exactly where
# execution is stuck), then terminates the run. Note: thread method ends the whole
# session rather than failing one test, so a hang fails the job in ~300s with a
# stack dump instead of running to the CI job limit. Tune 300s if real e2e timings
# push past it.
CMD ["pytest", "test/", "--timeout=300", "--timeout-method=thread"]
