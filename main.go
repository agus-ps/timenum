package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"crypto/tls"
)

// timenum: herramienta para enumeración de usuarios basada en tiempos de respuesta.
// - Soporta modo "URL simple" (-u) y "request template" (-r) con un único punto de inyección marcado con '*'
// - Iteraciones para promediar tiempos (-i)
// - Delay entre peticiones (-delay)
// - Proxy y opción para omitir verificación de certificados (--no-check-cert)
// - Verbose para ver cada petición (-v)
//
// Compilar:
//   go build -o timenum main.go

func main() {
	// Flags y ayuda
	requestFile := flag.String("r", "", "Archivo con petición HTTP completa. Usar '*' exactamente 1 vez como punto de inyección (en path o body).")
	urlParam := flag.String("u", "", "URL del endpoint para modo simple (ej: https://target.example/login).")
	wordlist := flag.String("w", "", "Archivo con lista de usuarios (uno por línea). Obligatorio.")
	iterations := flag.Int("i", 3, "Iteraciones por usuario para calcular tiempo promedio (default: 3).")
	verbose := flag.Bool("v", false, "Mostrar detalles de cada petición (tiempo y status).")
	proxy := flag.String("proxy", "", "Proxy a utilizar. Ej: http://127.0.0.1:8080")
	delay := flag.Int("delay", 0, "Delay en milisegundos entre iteraciones (útil para evitar rate limits).")
	noCertCheck := flag.Bool("no-check-cert", false, "No verificar certificado TLS (para testing / certs autofirmados).")
	httpsFlag := flag.Bool("https", false, "Forzar uso de https al construir URL desde plantilla (solo si el request template no contiene esquema).")
	showHeaders := flag.Bool("headers", false, "Si se usa -v, también muestra los headers de la primera respuesta.")
	flag.Usage = func() {
		usageText := `timenum - Enumeración basada en tiempo (time-based user enumeration)

USO:
  Modo URL simple:
    timenum -u <url> -w <wordlist> [opciones]

  Modo archivo (request template):
    timenum -r <request_file> -w <wordlist> [opciones]

REQUISITOS:
  - Debe especificarse -w (wordlist).
  - Usar **exactamente un** '*' en la plantilla para marcar el punto de inyección (path o body).
  - Si se usa -r, el archivo debe contener la primera línea con la request-line (ej: "POST /login HTTP/1.1")
    y un header Host: <host>.
    Formato aceptado de separación entre headers y body: \r\n\r\n o \n\n.

OPCIONES:
`
		fmt.Fprintln(os.Stderr, usageText)
		flag.PrintDefaults()
		examples := `

EJEMPLOS:
  1) Modo simple - POST con form-encoded:
     timenum -u "https://target.example/login" -w users.txt -i 5 -v --delay 100

  2) Modo plantilla - request HTTP completa (inyección con '*'):
     timenum -r request.txt -w users.txt -i 3 --proxy http://127.0.0.1:8080 --no-check-cert

  Ejemplo (request.txt):
    POST /login HTTP/1.1
    Host: target.example
    Content-Type: application/json

    {"username":"*","password":"wrongpass"}

NOTAS IMPORTANTES:
  - Esta herramienta mide tiempos de respuesta y status codes para detectar diferencias por usuario.
  - Usar responsablemente: pruebas solo en sistemas donde tengas autorización.
`
		fmt.Fprintln(os.Stderr, examples)
	}
	flag.Parse()

	// Validaciones básicas de flags
	if (*requestFile == "" && *urlParam == "") || *wordlist == "" {
		fmt.Fprintln(os.Stderr, "ERROR: Debés indicar una URL (-u) o un archivo de petición (-r), y una wordlist (-w).")
		flag.Usage()
		os.Exit(1)
	}

	// Abrir wordlist
	file, err := os.Open(*wordlist)
	if err != nil {
		fmt.Printf("Error al abrir wordlist: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Configurar transporte HTTP: proxy y verificación de certificados
	transport := &http.Transport{}
	if *proxy != "" {
		proxyUrl, err := url.Parse(*proxy)
		if err != nil {
			fmt.Printf("Error al parsear URL del proxy: %v\n", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyUrl)
		fmt.Printf("[*] Usando proxy: %s\n", *proxy)
	}
	if *noCertCheck {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		fmt.Println("[!] Advertencia: verificación de certificado TLS DESACTIVADA")
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // timeout razonable por petición
	}

	scanner := bufio.NewScanner(file)

	fmt.Println("Iniciando prueba de enumeración basada en tiempo...")
	if *requestFile != "" {
		fmt.Printf("Plantilla: %s\n", *requestFile)
	} else {
		fmt.Printf("URL: %s\n", *urlParam)
	}
	fmt.Printf("Wordlist: %s | Iteraciones: %d | Delay: %dms\n\n", *wordlist, *iterations, *delay)

	// Leer y preparar plantilla si aplica
	var requestTemplate []byte
	var isFileMode bool
	var injectionPoint string

	if *requestFile != "" {
		isFileMode = true
		requestTemplate, err = ioutil.ReadFile(*requestFile)
		if err != nil {
			fmt.Printf("Error leyendo archivo de petición: %v\n", err)
			os.Exit(1)
		}

		rawRequest := string(requestTemplate)

		// contabilizar ocurrencias de '*' en la request-line + body (no permitimos en headers)
		sections := strings.SplitN(rawRequest, "\n\n", 2)
		if len(sections) != 2 {
			sections = strings.SplitN(rawRequest, "\r\n\r\n", 2)
		}

		headerPart := sections[0]
		bodyPart := ""
		if len(sections) > 1 {
			bodyPart = sections[1]
		}

		lines := strings.Split(headerPart, "\n")
		requestLine := strings.TrimSpace(lines[0])

		injectionCount := strings.Count(requestLine, "*") + strings.Count(bodyPart, "*")
		if injectionCount != 1 {
			fmt.Println("ERROR: El punto de inyección (*) debe aparecer exactamente 1 vez (en request-line o body). No se permiten en headers.")
			os.Exit(1)
		}

		fmt.Printf("[*] Plantilla cargada desde: %s\n", *requestFile)
		injectionPoint = rawRequest
	}

	// Iterar wordlist
	for scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		if username == "" {
			continue
		}

		totalTime := time.Duration(0)
		var firstResponse *http.Response
		firstStatusCode := 0
		var firstHeaders http.Header

		for i := 0; i < *iterations; i++ {
			// Delay entre iteraciones (si corresponde)
			if i > 0 && *delay > 0 {
				time.Sleep(time.Duration(*delay) * time.Millisecond)
			}

			start := time.Now()

			var req *http.Request
			var err error

			if isFileMode {
				req, err = buildRequestFromTemplate(injectionPoint, username, *httpsFlag)
			} else {
				req, err = buildSimpleRequest(*urlParam, username)
			}

			if err != nil {
				fmt.Printf("Error creando petición para %s: %v\n", username, err)
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("Error enviando petición para %s: %v\n", username, err)
				continue
			}

			// Guardar la primera respuesta para inspección
			if i == 0 {
				firstResponse = resp
				firstStatusCode = resp.StatusCode
				firstHeaders = resp.Header
			} else {
				// Cerramos bodies de iteraciones posteriores
				resp.Body.Close()
			}

			elapsed := time.Since(start)
			totalTime += elapsed

			if *verbose {
				fmt.Printf("[%s] Intento %d: %v - Status: %d\n", username, i+1, elapsed, resp.StatusCode)
			}
		}

		// Cerrar body de la primera respuesta (si existe)
		if firstResponse != nil {
			firstResponse.Body.Close()
		}

		avgTime := totalTime / time.Duration(*iterations)
		fmt.Printf("Usuario: %-20s Tiempo promedio: %v - Status: %d\n", username, avgTime, firstStatusCode)

		if *verbose && *showHeaders && firstHeaders != nil {
			fmt.Println("  Headers recibidos (primera respuesta):")
			for k, v := range firstHeaders {
				fmt.Printf("    %s: %s\n", k, strings.Join(v, ", "))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error leyendo wordlist: %v\n", err)
	}
}

// buildRequestFromTemplate arma una petición HTTP a partir de una plantilla.
// - template: texto completo de la petición (request-line + headers + body)
// - username: valor que reemplaza el caracter '*' (exactamente 1 reemplazo)
// - httpsFlag: si true, construye la URL con https:// en lugar de http:// si el esquema no está presente
func buildRequestFromTemplate(template, username string, httpsFlag bool) (*http.Request, error) {
	// Reemplazamos una sola ocurrencia de '*'
	requestStr := strings.Replace(template, "*", username, 1)

	// Separamos headers y body (aceptamos \n\n o \r\n\r\n)
	parts := strings.SplitN(requestStr, "\n\n", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(requestStr, "\r\n\r\n", 2)
	}

	headers := parts[0]
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}

	headerLines := strings.Split(headers, "\n")
	firstLine := strings.TrimSpace(headerLines[0])
	headerLines = headerLines[1:]

	methodAndPath := strings.Fields(firstLine)
	if len(methodAndPath) < 2 {
		return nil, fmt.Errorf("formato inválido en archivo de petición (primera línea debe contener METHOD y PATH)")
	}

	method := methodAndPath[0]
	path := methodAndPath[1]

	// Buscar Host en headers
	var host string
	for _, line := range headerLines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			break
		}
	}

	if host == "" {
		return nil, fmt.Errorf("header 'Host' no encontrado en la plantilla")
	}

	// Construir URL: si path ya tiene esquema (http/https) usamos tal cual, sino armamos con host
	fullURL := ""
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		fullURL = path
	} else {
		scheme := "http://"
		if httpsFlag {
			scheme = "https://"
		}
		fullURL = scheme + host + path
	}

	req, err := http.NewRequest(method, fullURL, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}

	// Agregar headers (omitimos Host porque la URL ya la contiene)
	for _, line := range headerLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "host:") {
			continue
		}
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			req.Header.Set(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
		}
	}

	return req, nil
}

// buildSimpleRequest crea una petición POST x-www-form-urlencoded con username=...&password=wrongpass
// Es útil para endpoints de login simples sin plantilla.
func buildSimpleRequest(urlStr, username string) (*http.Request, error) {
	formData := fmt.Sprintf("username=%s&password=wrongpass", url.QueryEscape(username))
	req, err := http.NewRequest("POST", urlStr, bytes.NewBufferString(formData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

