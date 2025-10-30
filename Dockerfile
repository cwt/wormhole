# Define build-time arguments for version management
ARG PYTHON_BASE_IMAGE=docker.io/library/python:3.14-alpine
ARG POETRY_VERSION=2.2.1

# Stage 1: Build Stage
# This stage installs dependencies using Poetry into a virtual environment.
FROM ${PYTHON_BASE_IMAGE} as builder

# Update package database and upgrade packages
RUN apk update && apk upgrade --no-cache

# Re-declare ARG to bring it into the scope of this build stage
ARG POETRY_VERSION

# Set the working directory
WORKDIR /app

# Install poetry, the dependency manager
# We pin the version for consistent builds and use a virtual environment for poetry itself.
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
RUN apk add --no-cache gcc musl-dev libffi-dev make automake libtool file && \
    python -m venv $POETRY_HOME && \
    $POETRY_HOME/bin/pip install poetry==${POETRY_VERSION}

# Add poetry to the PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Copy all project files into the build context.
# It is recommended to have a .dockerignore file in your project root
# to exclude unnecessary files like .git, __pycache__, etc.
COPY . .

# Install project dependencies and the project itself, excluding the 'dev' group.
# --compile: Compile the dependencies to bytecode for performance.
# --without dev: Exclude development dependencies.
# Install uvloop first as it needs to be built from source in this container environment.
# Then install the project without performance extras as uvloop is already installed.
RUN apk add --no-cache gcc musl-dev libffi-dev make automake libtool file && \
    poetry run pip install Cython && \
    poetry run pip install --no-binary=uvloop --no-cache-dir uvloop && \
    poetry install --compile --without dev && \
    apk del gcc musl-dev libffi-dev make automake libtool file


# Stage 2: Final Runtime Stage
# This stage creates the final, lightweight image for running the application.
FROM ${PYTHON_BASE_IMAGE}

# Update package database and upgrade packages
RUN apk update && apk upgrade --no-cache

# Set a base application directory
WORKDIR /app

# Install only the necessary runtime dependencies and set up a non-root user.
RUN apk add --no-cache shadow && \
    adduser -D -h /home/wormhole -s /bin/sh wormhole && \
    apk del shadow

# Copy the virtual environment (which includes the installed project) from the builder stage
COPY --from=builder --chown=wormhole:wormhole /app/.venv ./.venv

# Copy the application source code itself from the builder stage.
# This ensures the code is found by the .pth file in site-packages.
COPY --from=builder --chown=wormhole:wormhole /app/wormhole ./wormhole/

# Set the PATH to include the virtual environment's bin directory
ENV PATH="/app/.venv/bin:$PATH"

# --- Configuration Persistence Setup ---
# Create a config directory and set ownership. This is performed as root.
RUN mkdir /config && chown wormhole:wormhole /config

# Mark the config directory as a volume to enable mounting and persistence
# for files like wormhole.passwd or an ad-block database.
VOLUME /config
# --- End Configuration Persistence Setup ---

# Switch to the non-root user for running the application
USER wormhole

# Set the runtime working directory. Users can mount their configuration
# files here, and wormhole can be run with arguments like '-a wormhole.passwd'.
WORKDIR /config

# Expose the default port for the Wormhole proxy.
# This serves as documentation for the user.
EXPOSE 8800/tcp

# Set the default command to run when the container starts.
CMD ["wormhole"]
