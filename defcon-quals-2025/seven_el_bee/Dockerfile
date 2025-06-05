# Use the official Elixir image
FROM elixir:latest

# Set the working directory inside the container
WORKDIR /app

# Install Hex and Rebar (build tools for Elixir)
RUN mix local.hex --force && \
    mix local.rebar --force

# Start the container in interactive mode

# Copy the application files into the container
COPY sevenelbee-27fa7927a4e12018ce0c2f88c7c3c430b4ba1118/ /app
RUN chmod +x -R /app
# Set the environment variable
ENV SECRET_KEY_BASE="aN/8DV9OiNgCe/outFn+ONXlfkoJfo7MxOmj3XDRDDG7RS/XvshxlAg2+YG+iPEv"
CMD ["bash"]