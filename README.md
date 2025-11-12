# timenum

Herramienta para enumeración de usuarios **basada en tiempos de respuesta** (time-based enumeration).

**Propósito:** medir diferencias de latencia / comportamiento en respuestas al probar distintos usernames contra un endpoint. Útil para detectar respuestas diferenciales (timing) o diferencias en códigos HTTP.

> ⚠️ Uso responsable: ejecutar solo en sistemas donde tengas autorización explícita.

---

## Características

- Modo **URL simple** (`-u`) para endpoints típicos (POST form-encoded).
- Modo **plantilla** (`-r`) que acepta una petición HTTP completa (request-line + headers + body) con EXACTAMENTE **un** `*` como punto de inyección (path o body).
- Promedia tiempos con múltiples iteraciones (`-i`).
- Delay configurable entre iteraciones (`--delay`).
- Soporte de proxy y opción para desactivar verificación TLS.
- `-v` verbose para ver tiempos por iteración; opción `--headers` para mostrar headers de la primera respuesta.

---

## Compilación

```bash
go build -o timenum main.go
````

O directamente:

```bash
go run main.go -h
```

---

## Uso

### 1) Modo URL simple

```bash
./timenum -u "https://target.example/login" -w users.txt -i 5 -v --delay 100
```

Este modo enviará un `POST` con `username=<user>&password=wrongpass` y medirá tiempos.

### 2) Modo plantilla (request file)

Ejemplo de `request.txt`:

```
POST /login HTTP/1.1
Host: target.example
Content-Type: application/json

{"username":"*","password":"wrongpass"}
```

Comando:

```bash
./timenum -r request.txt -w users.txt -i 3 --proxy http://127.0.0.1:8080 --no-check-cert
```

* El `*` se reemplaza por cada usuario.
* Debe haber exactamente **una** ocurrencia de `*` (en request-line o body).
* Si el path en la primera línea ya incluya `http://` o `https://`, se usará tal cual. Si no, la URL se arma con `http://<Host><path>`; podés forzar `https` con `--https`.

---

## Flags / Opciones

* `-r` Archivo de petición (plantilla) — usar `*` como punto de inyección.
* `-u` URL del endpoint (modo simple).
* `-w` Wordlist (uno por línea) — obligatorio.
* `-i` Iteraciones por usuario (default `3`).
* `-v` Verbose — imprime cada intento.
* `--proxy` Proxy (ej: `http://127.0.0.1:8080`).
* `--delay` Delay en ms entre iteraciones (ej: `100`).
* `--no-check-cert` No verificar certificado TLS (testing).
* `--https` Forzar esquema `https://` cuando se arma URL desde plantilla.
* `--headers` Si se usa `-v`, muestra headers de la primera respuesta.

---

## Salida

Por cada usuario verás una línea:

```
Usuario: <nombre>          Tiempo promedio: <duración> - Status: <http_code>
```

Si activás `-v`, además verás los tiempos de cada intento y códigos.

---

## Buenas prácticas / notas

* Ajustá `-i` y `--delay` para reducir falsos positivos por jitter de red.
* Usá un proxy (Burp) para inspeccionar tráfico si necesitás depurar la plantilla.
* Cuidado con sistemas con rate-limiting / WAF: incluir delay y/o rotar proxies si corresponde.
* Los resultados deben interpretarse en contexto: diferencias pequeñas pueden deberse a ruido de red.

---

## Ejemplos rápidos

* Test básico:

  ```bash
  ./timenum -u "https://target/login" -w users.txt -i 5 -v
  ```

* Test con plantilla JSON:

  ```bash
  ./timenum -r req.json -w users.txt -i 3 --delay 200 --https
  ```

---

## Licencia y responsabilidad

Esta herramienta es para **testing autorizado**. No me hago responsable por su uso indebido. Usala solo donde tengas permiso.

```
