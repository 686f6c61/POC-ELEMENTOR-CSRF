# Laboratorio: CSRF en Elementor 4.3.0/4.3.1 (bypass del nonce REST)
# Un target por fase del ataque, al estilo del lab CVE-2026-93485.

VICTIMA := http://localhost:8085
CONTROL := http://localhost:8086

# Credenciales de la puerta trasera (sobreescribibles por línea de comandos):
#   make click USUARIO=sombra CLAVE='Mi P@ss&2026!' EMAIL=sombra@lab.test
#   make reset USUARIO=sombra
USUARIO ?= csrfadmin
CLAVE ?= csrfadmin-PoC-2026
EMAIL ?= csrfadmin@lab.test
export POC_USER := $(USUARIO)
export POC_PASS := $(CLAVE)
export POC_MAIL := $(EMAIL)

.PHONY: help lab control fingerprint link click verify aportaciones hardening-demo \
        mitigacion-demo fuzz-subcadena detectar-iocs detectar-iocs-vivo blast-radius \
        demo-navegador demo-flip control-click full-demo reset capturas clean landing \
        ctf ctf-verificar ctf-clean

help: ## Lista de targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1;34m%-16s\033[0m %s\n", $$1, $$2}'

lab: ## Levanta la víctima: WP + Elementor 4.3.1 en :8085
	docker compose up -d --build db victima
	./scripts/esperar.sh $(VICTIMA)

control: ## Levanta el control negativo: Elementor 4.3.2 en :8086
	docker compose --profile control up -d --build
	./scripts/esperar.sh $(CONTROL)

fingerprint: ## FASE 1: reconnaissance pasivo del objetivo
	./exploit/01_fingerprint.sh $(VICTIMA)

link: ## FASE 2: genera enlace malicioso + correo de phishing simulado
	python3 exploit/02_craft_link.py --base-url $(VICTIMA) --out-dir exploit

click: ## FASE 3: simula el clic del admin (201 en víctima, 401 en control)
	./exploit/03_click_victim.sh $(VICTIMA) victima-4.3.1

control-click: ## FASE 3b: mismo enlace contra el control parchado (debe fallar)
	./exploit/03_click_victim.sh $(CONTROL) control-4.3.2 || [ $$? -eq 2 ]

verify: ## FASE 4: comprueba que csrfadmin es admin real (WP-CLI + wp-admin)
	./exploit/04_verificar_admin.sh $(VICTIMA)

aportaciones: ## FASE 6 (aportación propia): puerta silenciosa + cuenta dormida
	./exploit/06_aportaciones.sh $(VICTIMA)

hardening-demo: ## FASE 7 (aportación propia): el bypass anula el hardening anti-CSRF
	./exploit/07_hardening_bypass.sh $(VICTIMA)

mitigacion-demo: ## FASE 8: verifica la paliativa (experimento inactive) A/B/C
	./exploit/08_mitigacion_demo.sh $(VICTIMA)

fuzz-subcadena: ## Mini-fuzzer: matriz de variantes de la subcadena mágica
	python3 research/investigacion/fuzz_subcadena.py > research/investigacion/fuzz-resultados.md; cat research/investigacion/fuzz-resultados.md

detectar-iocs: ## Detector de IOCs sobre el log de ejemplo (líneas reales + benignas)
	cat research/investigacion/access-log-ejemplo.log | python3 scripts/detectar_iocs.py; test $$? -eq 1

detectar-iocs-vivo: ## Detector de IOCs sobre los logs EN VIVO de la víctima
	docker logs elementorcsrf-victima-1 2>&1 | python3 scripts/detectar_iocs.py || true

blast-radius: ## FASE 9: plugins por GET (core) + WooCommerce vs el bypass
	./exploit/09_blast_radius.sh $(VICTIMA)

NODE ?= $(shell command -v node 2>/dev/null || echo /opt/homebrew/bin/node)

demo-navegador: ## Demo con NAVEGADOR REAL: login + correo + clic -> 201 (CDP)
	python3 exploit/02_craft_link.py --base-url $(VICTIMA) \
	    --username demo-navegador --password demo-navegador-PoC-2026 \
	    --email demo-navegador@lab.test >/dev/null
	$(NODE) scripts/capturas/demo_navegador.mjs demo-navegador demo-navegador-PoC-2026

demo-flip: ## FASE 5: root cause en vivo, diff víctima(4.3.1) vs control(4.3.2)
	./exploit/05_demo_root_cause.sh

full-demo: lab fingerprint link click verify aportaciones hardening-demo control control-click demo-flip ## Todo el encadenado

capturas: ## Regenera la galería PNG en docs/img/ (terminal + navegador + og)
	sh scripts/capturas/generar.sh

reset: ## Borra la puerta trasera del lab víctima (usuario: USUARIO=..., por defecto csrfadmin)
	docker compose exec -T victima wp user delete $(USUARIO) --allow-root --yes || true

ctf: ## Levanta el CTF: reto en :8087 + bot víctima en :8089 (ver ctf/README.md)
	docker compose --profile ctf up -d --build db-ctf ctf ctf-bot
	./scripts/esperar.sh http://localhost:8087
	@echo "CTF listo: reto en http://localhost:8087 · bot en http://localhost:8089"

ctf-verificar: ## Verifica una flag: make ctf-verificar N=2 VAL='CTF{...}'
	./ctf/verificar.sh "$(N)" "$(VAL)"

ctf-clean: ## Desmonta el CTF (contenedor + bot + volumen)
	docker compose --profile ctf rm -sf db-ctf ctf ctf-bot >/dev/null 2>&1 || true
	docker volume rm elementorcsrf_db_ctf_data elementorcsrf_ctf_html >/dev/null 2>&1 || true
	@echo "CTF desmontado"

clean: ## Destruye contenedores, volúmenes y redes del lab
	docker compose --profile control --profile ctf down -v --remove-orphans

landing: ## Sirve la landing didáctica en :8095 (docs/, publicable en GitHub Pages)
	cd docs && python3 -m http.server 8095
