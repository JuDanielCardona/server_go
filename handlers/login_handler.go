package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Credentials struct {
	Usuario string `json:"usuario"`
	Clave   string `json:"clave"`
}

func Login_handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if creds.Usuario == "" || creds.Clave == "" {
		http.Error(w, "Los atributos 'usuario' y 'clave' son obligatorios", http.StatusBadRequest)
		return
	}

	token := jwt.New(jwt.SigningMethodES256)
	claims := token.Claims.(jwt.MapClaims)
	claims["usuario"] = creds.Usuario
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["iss"] = "ingesis.uniquindio.edu.co"

	tokenString, err := token.SignedString([]byte("contraseña"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Responder con el token JWT
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}
