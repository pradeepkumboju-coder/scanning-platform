# Multi-stage build for security scanning tools
FROM node:20.17.0-alpine AS base

# Install system dependencies
RUN apk add --no-cache \
    git \
    curl \
    wget \
    bash \
    jq \
    && rm -rf /var/cache/apk/*

# Install pnpm globally
RUN npm install -g pnpm@8.6.0

# Create working directory
WORKDIR /app

# Install core security scanning tools
FROM base AS tools

# Install is-my-node-vulnerable
RUN npm install -g is-my-node-vulnerable@1.2.4

# Install better-npm-audit
RUN npm install -g better-npm-audit@3.7.3

# Install commander for script argument parsing
RUN npm install -g commander@11.0.0

# Create reports directory
RUN mkdir -p /app/reports /app/scripts /app/templates

# Final stage
FROM tools AS scanner

# Copy scanning scripts
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

# Create templates directory (for future use)
RUN mkdir -p /app/templates

# Set environment variables
ENV NODE_ENV=production
ENV SCAN_OUTPUT_DIR=/app/reports
ENV PATH="/app/scripts:$PATH"

# Create a non-root user for security
RUN addgroup -g 1001 scanner && \
    adduser -D -u 1001 -G scanner scanner && \
    chown -R scanner:scanner /app

USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node --version && npm --version && which is-my-node-vulnerable && which better-npm-audit

# Default command
CMD ["/app/scripts/run-security-scan.sh", "--help"]