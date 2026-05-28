FROM node:20-slim

# Create non-root user
RUN adduser --disabled-password --gecos "" nodeuser

WORKDIR /app

# Set production environment
ENV NODE_ENV=production

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production && \
    # Change ownership of /app directory to nodeuser
    chown -R nodeuser:nodeuser /app

# Switch to non-root user
USER nodeuser

# Copy application files
COPY --chown=nodeuser:nodeuser . .

EXPOSE 3000 514/udp

# Default command (can be overridden by docker-compose)
CMD ["node", "server.js"]