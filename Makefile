# Makefile - Web-Sec Cyber-Deck Automation

IMAGE_NAME ?= web-sec
TAG ?= latest

.PHONY: all help test lint docker-build docker-run run clean

all: help

help:
	@echo "Web-Sec Cyber-Deck Suite // Comandos Disponibles:"
	@echo "  make test          - Ejecutar suite de pruebas unitarias e integradas (unittest)"
	@echo "  make lint          - Validación sintáctica de todos los módulos Python"
	@echo "  make docker-build  - Construir imagen Docker de la suite ($(IMAGE_NAME):$(TAG))"
	@echo "  make docker-run    - Ejecutar contenedor Docker interactivo con volumen de outputs"
	@echo "  make run           - Lanzar Web-Sec Cyber-Deck de forma local"
	@echo "  make clean         - Limpiar archivos de cache y temporales"

test:
	python3 -m unittest discover -s tests -p "test_*.py" -v

lint:
	python3 -m py_compile main.py mode2_richlive.py websec_core.py storage_vault.py plugin_runner.py credential_scanner.py browser_client.py privacy_guard.py level_handlers/*.py

docker-build:
	docker build -t $(IMAGE_NAME):$(TAG) .

docker-run:
	docker run -it --rm \
		-v "$$(pwd)/outputs:/app/outputs" \
		-v "$$(pwd)/allowed_targets.txt:/app/allowed_targets.txt:ro" \
		$(IMAGE_NAME):$(TAG)

run:
	./run.sh

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f outputs/*.tmp.*
