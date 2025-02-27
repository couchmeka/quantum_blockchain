# Makefile for Asterisk Quantum Security Module

# Default container name - modify if yours is different
CONTAINER_NAME ?= quantum-sip-docker-asterisk-1

# Paths inside the container
CONTAINER_SRC_DIR ?= /usr/src/asterisk_modules/res_quantum
CONTAINER_MODULE_DIR ?= /usr/lib/asterisk/modules

# Module name
MODULE = res_quantum.so

# Colors for better readability
GREEN=\033[0;32m
RED=\033[0;31m
YELLOW=\033[0;33m
NC=\033[0m # No Color

# Default target
all: build install check

# In-container compilation
build:
	@echo "$(YELLOW)Building quantum module inside container...$(NC)"
	@docker exec -i $(CONTAINER_NAME) bash -c "cd $(CONTAINER_SRC_DIR) && \
		gcc -shared -fPIC -g -O2 -o $(MODULE) res_quantum.c \
		-I/usr/include/asterisk -D_GNU_SOURCE \
		-DAST_MODULE_SELF_SYM=__internal_res_quantum_self \
		-DAST_MODULE=\\\"res_quantum\\\"" || { echo "$(RED)Build failed!$(NC)"; exit 1; }
	@echo "$(GREEN)Quantum module built inside container$(NC)"
	@docker exec -i $(CONTAINER_NAME) ls -la $(CONTAINER_SRC_DIR)/$(MODULE)

# Install the module inside the container
install:
	@echo "$(YELLOW)Installing module inside container...$(NC)"
	@docker exec -i $(CONTAINER_NAME) bash -c "cp $(CONTAINER_SRC_DIR)/$(MODULE) $(CONTAINER_MODULE_DIR)/ && \
		chmod 644 $(CONTAINER_MODULE_DIR)/$(MODULE)" || { echo "$(RED)Installation failed!$(NC)"; exit 1; }
	@echo "$(GREEN)Module installed$(NC)"
	@docker exec -i $(CONTAINER_NAME) ls -la $(CONTAINER_MODULE_DIR)/$(MODULE)

# Configure Asterisk
config:
	@echo "$(YELLOW)Configuring Asterisk...$(NC)"
	@docker exec -i $(CONTAINER_NAME) bash -c "if ! grep -q 'res_quantum.so' /etc/asterisk/modules.conf; then \
		echo 'load => res_quantum.so' >> /etc/asterisk/modules.conf; \
		echo '$(GREEN)Added res_quantum to modules.conf$(NC)'; \
	else \
		echo '$(YELLOW)res_quantum already in modules.conf$(NC)'; \
	fi"
	@docker exec -i $(CONTAINER_NAME) bash -c "if [ ! -f /etc/asterisk/quantum.conf ]; then \
		cat > /etc/asterisk/quantum.conf << 'EOL' \
[general]\n\
quantum_enabled=yes\n\
org_id=Hospital_A\n\
key_store=/etc/asterisk/keys\n\
\n\
[quantum_keys]\n\
falcon_public_key=Hospital_A_falcon_public.pem\n\
falcon_private_key=Hospital_A_falcon_private.pem\n\
kyber_public_key=Hospital_A_kyber_public.pem\n\
kyber_private_key=Hospital_A_kyber_private.pem\n\
\n\
[security]\n\
refresh_interval=3600\n\
key_rotation_enabled=yes\n\
EOL\n \
		echo '$(GREEN)Created quantum.conf$(NC)'; \
	else \
		echo '$(YELLOW)quantum.conf already exists$(NC)'; \
	fi"

# Load the module
load:
	@echo "$(YELLOW)Loading res_quantum module...$(NC)"
	@docker exec -i $(CONTAINER_NAME) asterisk -rx "module load res_quantum.so" || echo "$(RED)Failed to load module$(NC)"

# Check the module status
check:
	@echo "$(YELLOW)Checking module status...$(NC)"
	@docker exec -i $(CONTAINER_NAME) asterisk -rx "module show like res_quantum" || echo "$(RED)Failed to check module status$(NC)"

# Show Asterisk uptime
uptime:
	@echo "$(YELLOW)Checking Asterisk uptime...$(NC)"
	@docker exec -i $(CONTAINER_NAME) asterisk -rx "core show uptime" || echo "$(RED)Failed to get uptime$(NC)"

# View latest logs
logs:
	@echo "$(YELLOW)Viewing Asterisk logs...$(NC)"
	@docker exec -i $(CONTAINER_NAME) bash -c "if [ -f /var/log/asterisk/messages ]; then \
		tail -n 100 /var/log/asterisk/messages; \
	elif [ -f /var/log/asterisk/full ]; then \
		tail -n 100 /var/log/asterisk/full; \
	else \
		echo '$(RED)No log files found!$(NC)'; \
		find /var/log -name '*aster*' -type f; \
	fi"

# Follow logs in real-time
follow-logs:
	@echo "$(YELLOW)Following Asterisk logs in real-time...$(NC)"
	@docker exec -it $(CONTAINER_NAME) bash -c "if [ -f /var/log/asterisk/messages ]; then \
		tail -f /var/log/asterisk/messages; \
	elif [ -f /var/log/asterisk/full ]; then \
		tail -f /var/log/asterisk/full; \
	else \
		echo '$(RED)No log files found!$(NC)'; \
		find /var/log -name '*aster*' -type f; \
	fi"

# Debug Asterisk
debug:
	@echo "$(YELLOW)Running Asterisk diagnostics...$(NC)"
	@echo "$(YELLOW)1. Container running status:$(NC)"
	@docker ps | grep $(CONTAINER_NAME) || echo "$(RED)Container not running!$(NC)"
	@echo "$(YELLOW)2. Module files:$(NC)"
	@docker exec -i $(CONTAINER_NAME) find / -name "res_quantum*" 2>/dev/null || echo "$(RED)No module files found$(NC)"
	@echo "$(YELLOW)3. Asterisk config files:$(NC)"
	@docker exec -i $(CONTAINER_NAME) ls -la /etc/asterisk/ || echo "$(RED)No config directory$(NC)"
	@echo "$(YELLOW)4. Asterisk uptime:$(NC)"
	@docker exec -i $(CONTAINER_NAME) asterisk -rx "core show uptime" || echo "$(RED)Cannot get uptime$(NC)"
	@echo "$(YELLOW)5. Asterisk modules:$(NC)"
	@docker exec -i $(CONTAINER_NAME) asterisk -rx "module show" || echo "$(RED)Cannot list modules$(NC)"
	@echo "$(YELLOW)6. Log directory:$(NC)"
	@docker exec -i $(CONTAINER_NAME) ls -la /var/log/asterisk/ || echo "$(RED)No log directory$(NC)"
	@echo "$(YELLOW)7. Process status:$(NC)"
	@docker exec -i $(CONTAINER_NAME) ps aux | grep asterisk || echo "$(RED)No asterisk processes$(NC)"

# Clean build artifacts inside container
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@docker exec -i $(CONTAINER_NAME) bash -c "rm -f $(CONTAINER_SRC_DIR)/*.o $(CONTAINER_SRC_DIR)/$(MODULE)" || echo "$(RED)Clean failed$(NC)"

# Restart Asterisk
restart:
	@echo "$(YELLOW)Restarting Asterisk...$(NC)"
	@docker exec -i $(CONTAINER_NAME) asterisk -rx "core restart gracefully" || echo "$(RED)Restart failed$(NC)"

# Full procedure
full-setup: clean build install config load check logs

# Phony targets
.PHONY: all build install config load check uptime logs follow-logs debug clean restart full-setup