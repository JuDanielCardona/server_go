# Usa la imagen de Go como base
FROM golang:latest

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el binario de tu aplicación al contenedor
COPY . .

# Expone el puerto 80 en el contenedor
EXPOSE 80

# Define el comando de inicio
CMD ["go", "run", "main.go"]
