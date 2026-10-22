import http.server
import socketserver
import os

PORT = 8999
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # Simulamos fuga intencional de versión de backend y falta de CSP / HSTS
        self.send_header('Server', 'Apache/2.4.41 (Ubuntu) PHP/7.4.3')
        self.send_header('X-Powered-By', 'PHP/7.4.3')
        super().end_headers()

    def do_GET(self):
        # Endpoint simulado para /about
        if self.path == '/about':
            self.path = '/about.html'
        return super().do_GET()

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        print(f"Servidor de prueba corriendo en http://localhost:{PORT}")
        httpd.serve_forever()
