# Use the official Elixir image
FROM elixir:latest

# Set the working directory inside the container
WORKDIR /app

# Install Hex and Rebar (build tools for Elixir)
RUN mix local.hex --force && \
    mix local.rebar --force

# Start the container in interactive mode

# Copy the application files into the container
COPY dist/ /app
RUN chmod +x -R /app
# Set the environment variable
CMD ["bash"]