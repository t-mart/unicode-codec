src-paths = unicodec.py tests

.PHONY: all
all: isort black flake8 pylint mypy all

.PHONY: mypy
mypy:
	mypy $(src-paths)

.PHONY: isort
isort:
	isort $(src-paths)

.PHONY: flake8
flake8:
	flake8 $(src-paths)

.PHONY: pylint
pylint:
	pylint $(src-paths)

.PHONY: black
black:
	black $(src-paths)

.PHONY: test
test:
	pytest --cov=unicodec tests/