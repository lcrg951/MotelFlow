# API para cambiar estado y tiempo de habitación
import json  # NÓMINA: convierte los datos de nómina a texto JSON antes de cifrarlos
import os
import re
import secrets
import time
# NÓMINA: se agregó "date" para manejar las fechas de los periodos de pago
from datetime import date, datetime, timezone, timedelta
# NÓMINA: se agregaron ROUND_CEILING (redondear hacia arriba, para el ajuste de
# nómina) y ROUND_HALF_UP (redondeo normal al peso, para mostrar los valores)
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
from psycopg2.extras import RealDictCursor
# NÓMINA / SEGURIDAD: librería de cifrado (pip install cryptography). Fernet
# cifra y descifra con una clave secreta; InvalidToken es el error que lanza
# cuando el texto cifrado fue alterado o la clave no es la correcta.
from cryptography.fernet import Fernet, InvalidToken


# =====================================================================
# SEGURIDAD: Carga de variables de entorno desde un archivo .env
# ---------------------------------------------------------------------
# Las credenciales (clave secreta, contraseña de la BD) ya NO van escritas
# en el código. Se leen de variables de entorno. Para desarrollo local se
# pueden poner en un archivo .env (que está en .gitignore y nunca se sube
# a GitHub). Este cargador es mínimo para no agregar dependencias nuevas.
# Las variables que ya existan en el sistema tienen prioridad sobre el .env.
# =====================================================================
def cargar_env(ruta=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')):
    if not os.path.exists(ruta):
        return
    with open(ruta, encoding='utf-8') as archivo:
        for linea in archivo:
            linea = linea.strip()
            if not linea or linea.startswith('#') or '=' not in linea:
                continue
            clave, valor = linea.split('=', 1)
            os.environ.setdefault(clave.strip(), valor.strip().strip('"').strip("'"))

cargar_env()

# SEGURIDAD: el modo debug solo se activa explícitamente (FLASK_DEBUG=1).
# Con debug activo, Flask muestra una consola interactiva que permite
# ejecutar código en el servidor: jamás debe estar encendido en producción.
MODO_DEBUG = os.environ.get('FLASK_DEBUG') == '1'

app = Flask(__name__)

# SEGURIDAD: clave secreta leída del entorno. Con ella se firman las cookies
# de sesión; si alguien la conoce puede falsificar una sesión de admin.
# Si no está definida se genera una aleatoria (las sesiones se pierden al
# reiniciar el servidor, pero nunca se usa una clave conocida).
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
if not os.environ.get('SECRET_KEY'):
    app.logger.warning('SECRET_KEY no definida: se usa una clave temporal aleatoria.')

# SEGURIDAD: configuración de la cookie de sesión.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # JavaScript no puede leer la cookie (mitiga robo por XSS)
    SESSION_COOKIE_SAMESITE='Lax',      # El navegador no la envía en peticiones POST desde otros sitios
    SESSION_COOKIE_SECURE=not MODO_DEBUG,  # En producción solo viaja por HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # La sesión expira tras 8 horas (un turno)
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # Rechaza peticiones de más de 1 MB
)

# SEGURIDAD: si la app corre detrás de un proxy (Render, Heroku, Nginx),
# esto permite conocer la IP real del cliente y si la conexión es HTTPS.
# Solo se activa con CONFIAR_PROXY=1, porque sin proxy un atacante podría
# falsificar la cabecera X-Forwarded-For.
if os.environ.get('CONFIAR_PROXY') == '1':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# SEGURIDAD: configuración de conexión a NeonDB PostgreSQL desde el entorno.
# Se acepta DATABASE_URL (formato típico de los servicios en la nube) o las
# variables separadas DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT.
DATABASE_URL = os.environ.get('DATABASE_URL')
DB_CONFIG = {
    'dbname': os.environ.get('DB_NAME', 'neondb'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', 5432)),
    'sslmode': 'require'
}

def get_db_connection():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL, sslmode='require', cursor_factory=RealDictCursor)
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    return conn

LOCAL_ZONE = ZoneInfo('America/Bogota')

def convertir_a_hora_local(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(LOCAL_ZONE)


# =====================================================================
# SEGURIDAD: Protección CSRF (Cross-Site Request Forgery)
# ---------------------------------------------------------------------
# Sin esto, una página maliciosa podría hacer que el navegador de un admin
# con sesión abierta envíe formularios a MotelFlow (crear usuarios, dar
# permisos, registrar ventas...). Cada sesión recibe un token aleatorio que
# debe acompañar toda petición POST: en formularios como campo oculto
# "csrf_token" y en fetch() como cabecera "X-CSRFToken".
# =====================================================================
def generar_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

# Permite usar {{ csrf_token() }} dentro de las plantillas
app.jinja_env.globals['csrf_token'] = generar_csrf_token

@app.before_request
def proteger_csrf():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    token_sesion = session.get('_csrf_token')
    token_enviado = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    # compare_digest compara en tiempo constante (evita ataques de temporización)
    if not token_sesion or not token_enviado or not secrets.compare_digest(token_sesion, token_enviado):
        app.logger.warning('CSRF inválido en %s desde %s', request.path, request.remote_addr)
        abort(400)


# =====================================================================
# SEGURIDAD: Cabeceras HTTP de seguridad en todas las respuestas
# =====================================================================
@app.after_request
def agregar_cabeceras_seguridad(respuesta):
    # Impide que el navegador "adivine" el tipo de archivo (evita ejecutar subidas como script)
    respuesta.headers['X-Content-Type-Options'] = 'nosniff'
    # Impide que otra web incruste MotelFlow en un iframe (clickjacking)
    respuesta.headers['X-Frame-Options'] = 'DENY'
    # No envía la URL completa a sitios externos (p. ej. al abrir WhatsApp)
    respuesta.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Desactiva APIs del navegador que la app no usa
    respuesta.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # Política de contenido: solo se cargan scripts, estilos y medios del propio
    # servidor (y las fuentes de Google). 'unsafe-inline' es necesario porque las
    # plantillas usan <script> y onclick en línea.
    respuesta.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "media-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    # Con HTTPS, obliga al navegador a usar siempre HTTPS durante un año
    if request.is_secure:
        respuesta.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Las páginas internas no se guardan en caché: tras cerrar sesión, el botón
    # "Atrás" no debe mostrar datos de usuarios, ventas o turnos
    if 'usuario' in session:
        respuesta.headers['Cache-Control'] = 'no-store'
    return respuesta


# =====================================================================
# SEGURIDAD: Manejadores de errores
# ---------------------------------------------------------------------
# Muestran un mensaje genérico en lugar de detalles internos (rutas,
# consultas SQL, trazas de Python) que le darían pistas a un atacante.
# =====================================================================
MENSAJES_ERROR = {
    400: 'Solicitud inválida o formulario vencido. Recarga la página e inténtalo de nuevo.',
    403: 'No tienes permisos para realizar esta acción.',
    404: 'La página solicitada no existe.',
    405: 'Método no permitido.',
    413: 'La información enviada es demasiado grande.',
    500: 'Ocurrió un error interno. Inténtalo más tarde.',
}

def responder_error(codigo):
    mensaje = MENSAJES_ERROR.get(codigo, 'Error')
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'ok': False, 'msg': mensaje}), codigo
    return f'<h2>Error {codigo}</h2><p>{mensaje}</p><p><a href="/">Volver al inicio</a></p>', codigo

for _codigo in MENSAJES_ERROR:
    app.register_error_handler(_codigo, lambda e, c=_codigo: responder_error(c))


# =====================================================================
# SEGURIDAD: Funciones de validación de datos de entrada
# ---------------------------------------------------------------------
# Nunca se confía en lo que llega del navegador: el usuario puede modificar
# el HTML o enviar peticiones a mano. Cada función devuelve None si el dato
# no es válido.
# =====================================================================
REGEX_CORREO = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def leer_entero(valor, minimo=None, maximo=None):
    try:
        numero = int(str(valor).strip())
    except (TypeError, ValueError):
        return None
    if (minimo is not None and numero < minimo) or (maximo is not None and numero > maximo):
        return None
    return numero

def leer_decimal(valor, minimo=Decimal('0'), maximo=Decimal('1000000000')):
    try:
        numero = Decimal(str(valor).strip())
    except (InvalidOperation, TypeError, ValueError):
        return None
    # is_finite descarta valores como "NaN" o "Infinity"
    if not numero.is_finite() or numero < minimo or numero > maximo:
        return None
    return numero

def leer_texto(valor, max_largo, requerido=True):
    texto = (valor or '').strip()
    if (requerido and not texto) or len(texto) > max_largo:
        return None
    return texto


# =====================================================================
# SEGURIDAD: Contraseñas cifradas (hash)
# ---------------------------------------------------------------------
# Antes las contraseñas se guardaban en texto plano: cualquiera con acceso
# a la BD las veía. Ahora se guarda un hash (scrypt, con sal aleatoria) que
# no se puede revertir. Los usuarios antiguos se migran automáticamente: la
# primera vez que inician sesión con su contraseña en texto plano, esta se
# reemplaza por su hash.
# =====================================================================
LONGITUD_MINIMA_CONTRASENA = 8
PREFIJOS_HASH = ('scrypt:', 'pbkdf2:')
# Hash ficticio para comparar cuando el correo no existe, así la respuesta
# tarda lo mismo y no revela qué correos están registrados
HASH_FICTICIO = generate_password_hash(secrets.token_hex(16))

def es_hash(contrasena_guardada):
    return (contrasena_guardada or '').startswith(PREFIJOS_HASH)

def verificar_contrasena(usuario, contrasena):
    guardada = usuario['contrasena'] or ''
    if es_hash(guardada):
        return check_password_hash(guardada, contrasena)
    # Contraseña antigua en texto plano: comparar y migrar a hash
    if secrets.compare_digest(guardada.encode('utf-8'), contrasena.encode('utf-8')):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE usuario SET contrasena = %s WHERE id = %s",
                    (generate_password_hash(contrasena), usuario['id']))
        conn.commit()
        cur.close()
        conn.close()
        return True
    return False


# =====================================================================
# SEGURIDAD: Límite de intentos de inicio de sesión (fuerza bruta)
# ---------------------------------------------------------------------
# Tras 5 intentos fallidos con el mismo correo desde la misma IP, se bloquea
# el login por 5 minutos. Se guarda en memoria del servidor (se reinicia al
# reiniciar la app), suficiente para frenar ataques automatizados.
# =====================================================================
MAX_INTENTOS_LOGIN = 5
MINUTOS_BLOQUEO = 5
intentos_login = {}  # clave -> {'fallos': int, 'bloqueado_hasta': timestamp}

def clave_intentos(correo):
    return f"{request.remote_addr}|{correo.lower()}"

def login_bloqueado(clave):
    registro = intentos_login.get(clave)
    return bool(registro and registro['bloqueado_hasta'] > time.time())

def registrar_fallo_login(clave):
    registro = intentos_login.setdefault(clave, {'fallos': 0, 'bloqueado_hasta': 0})
    registro['fallos'] += 1
    if registro['fallos'] >= MAX_INTENTOS_LOGIN:
        registro['fallos'] = 0
        registro['bloqueado_hasta'] = time.time() + MINUTOS_BLOQUEO * 60
        app.logger.warning('Login bloqueado temporalmente para %s', clave)


# Función para obtener usuario por correo
def obtener_usuario_por_correo(correo):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM usuario WHERE correo = %s", (correo,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    return usuario

# SEGURIDAD: devuelve el usuario de la sesión solo si sigue existiendo y está
# Activo. Si un admin desactiva a un colaborador, este pierde el acceso en su
# siguiente clic, aunque tenga la sesión abierta.
def obtener_usuario_actual():
    if 'usuario' not in session:
        return None
    usuario = obtener_usuario_por_correo(session['usuario'])
    if not usuario or (usuario.get('estado') or '').lower() != 'activo':
        session.clear()
        return None
    return usuario

def es_admin(usuario):
    return bool(usuario) and (usuario['rol'] or '').lower() == 'admin'

PANELES = ['habitaciones', 'turnos', 'inventario', 'ventas', 'nomina', 'usuarios', 'permisos', 'aseo']

# Función para obtener los permisos del usuario actual
def obtener_permisos_usuario():
    usuario = obtener_usuario_actual()
    if not usuario:
        return []
    if es_admin(usuario):
        return list(PANELES)
    else:
        # Colaborador: obtener permisos asignados
        if usuario.get('permisos'):
            # SEGURIDAD: solo se aceptan nombres de panel conocidos
            return [p.strip() for p in usuario['permisos'].split(',') if p.strip() in PANELES]
        return []

# Función para validar si el usuario tiene permiso para un panel
def tiene_permiso(panel_requerido):
    permisos = obtener_permisos_usuario()
    return panel_requerido in permisos

# Función para redirigir si no tiene permiso
def validar_acceso(panel_requerido):
    if not tiene_permiso(panel_requerido):
        # SEGURIDAD: se registra el intento de acceso no autorizado
        app.logger.warning('Acceso denegado a "%s" para %s', panel_requerido, session.get('usuario', 'anónimo'))
        flash('No tienes permisos para acceder a este módulo.')
        return redirect(url_for('panel_admin'))
    return None

# Función para obtener el turno abierto de un usuario
def obtener_turno_abierto_usuario(usuario_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM turno WHERE id_usuario = %s AND estado IN ('Abierto', 'abierto') ORDER BY id DESC LIMIT 1", (usuario_id,))
    turno = cur.fetchone()
    cur.close()
    conn.close()
    return turno

DECORACIONES = [
    {
        'id': 1,
        'nombre': 'Decoración basica',
        'descripcion': 'Pétalos de rosa, velas aromáticas y luz tenue.',
        'precio': 25000,
        'imagen': 'img/aniversario.jpg'
    }
]

# Catálogo de habitaciones
ROOMS = [
    {
        'id': 1,
        'nombre': 'Habitación rubí',
        'descripcion': 'Habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación y baño privado.',
        'precio': 60000,
        'imagen': 'img/rubi.jpeg'
    },
    {
        'id': 2,
        'nombre': 'Habitación Zafiro',
        'descripcion': 'Ambiente íntimo, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado y camilla.',
        'precio': 65000,
        'imagen': 'img/zafiro.jpeg'
    },
    {
        'id': 3,
        'nombre': 'Habitación Diamante',
        'descripcion': 'Comodidad y privacidad, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado, camilla y jacuzzi.',
        'precio': 90000,
        'imagen': 'img/diamante.jpeg'
    },
    {
        'id': 4,
        'nombre': 'Habitación platino',
        'descripcion': 'Espacio moderno, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado, camilla, jacuzzi, sillon, sonio de alta calidad y sauna a petición',
        'precio': 120000,
        'imagen': 'img/platino.jpeg'
    }
]


TIEMPOS = [
    {
        'id': 'rato',
        'nombre': 'Rato',
        'precio': 40000
    },
    {
        'id': 'amanecida',
        'nombre': 'Amanecida',
        'precio': 70000
    }
]

# SEGURIDAD: valores permitidos para los campos que vienen de listas fijas
ROLES_VALIDOS = ('admin', 'colaborador')
ESTADOS_USUARIO = ('Activo', 'Inactivo')
ESTADOS_HABITACION = ('Libre', 'Ocupada', 'Sucia')
TIEMPOS_HABITACION = ('rato', 'amanecida')
# Las reservas viven en la cookie de sesión (máx. ~4 KB), por eso se limitan
MAX_RESERVAS_CARRITO = 10

@app.route('/')
def index():
    return render_template('index.html', rooms=ROOMS, decoraciones=DECORACIONES, tiempos=TIEMPOS)


@app.route('/cart')
def cart():
    reservas = session.get('reservas', [])
    total = 0
    for r in reservas:
        total += r['habitacion']['precio']
        for deco in r.get('decoraciones', []):
            total += deco['precio']
        if 'tiempo' in r and r['tiempo']:
            total += r['tiempo']['precio']
    return render_template('cart.html', reservas=reservas, total=total)

# Ruta para reservar habitación, decoraciones y tiempo
@app.route('/reservar', methods=['POST'])
def reservar():
    # SEGURIDAD: antes int(None) hacía caer la app con error 500
    room_id = leer_entero(request.form.get('room_id'), minimo=1)
    deco_ids = request.form.getlist('decoraciones')
    tiempo_id = request.form.get('tiempo')
    # Los precios salen siempre del catálogo del servidor, nunca del formulario
    room = next((r for r in ROOMS if r['id'] == room_id), None)
    decoraciones = [d for d in DECORACIONES if str(d['id']) in deco_ids]
    tiempo = next((t for t in TIEMPOS if t['id'] == tiempo_id), None)
    if room:
        reservas = session.get('reservas', [])
        if len(reservas) >= MAX_RESERVAS_CARRITO:
            flash('Has alcanzado el máximo de reservas en el carrito.')
            return redirect(url_for('cart'))
        reservas.append({'habitacion': room, 'decoraciones': decoraciones, 'tiempo': tiempo})
        session['reservas'] = reservas
    return redirect(url_for('cart'))



# Ruta de login con autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = (request.form.get('usuario') or '').strip()
        contrasena = request.form.get('contrasena') or ''
        clave = clave_intentos(correo)

        # SEGURIDAD: bloqueo temporal tras demasiados intentos fallidos
        if login_bloqueado(clave):
            flash(f'Demasiados intentos fallidos. Espera {MINUTOS_BLOQUEO} minutos e inténtalo de nuevo.')
            return redirect(url_for('login'))

        # SEGURIDAD: se descartan entradas vacías o absurdamente largas
        usuario = None
        if correo and contrasena and len(correo) <= 100 and len(contrasena) <= 128:
            usuario = obtener_usuario_por_correo(correo)

        if usuario and verificar_contrasena(usuario, contrasena):
            if (usuario.get('estado') or '').lower() != 'activo':
                flash('Tu usuario está inactivo. Comunícate con el administrador.')
                return redirect(url_for('login'))
            intentos_login.pop(clave, None)
            # SEGURIDAD: se limpia la sesión anterior antes de autenticar
            # (evita la "fijación de sesión") y se genera un token CSRF nuevo
            session.clear()
            session.permanent = True
            session['usuario'] = usuario['correo']
            session['rol'] = usuario['rol']
            app.logger.info('Inicio de sesión exitoso: %s', usuario['correo'])
            # Ambos Admin y Colaborador van a /admin que redirige a /panel_admin
            return redirect(url_for('admin'))
        else:
            if not usuario:
                # Misma demora que con un usuario real (no revela si el correo existe)
                check_password_hash(HASH_FICTICIO, contrasena)
            registrar_fallo_login(clave)
            app.logger.warning('Inicio de sesión fallido para "%s" desde %s', correo[:100], request.remote_addr)
            # Mensaje genérico: no se indica si falló el correo o la contraseña
            flash('Usuario o contraseña incorrectos.')
            return redirect(url_for('login'))
    return render_template('login.html')

# Ruta para eliminar una reserva por índice
@app.route('/eliminar/<int:idx>', methods=['POST'])
def eliminar(idx):
    reservas = session.get('reservas', [])
    if 0 <= idx < len(reservas):
        reservas.pop(idx)
        session['reservas'] = reservas
    return redirect(url_for('cart'))



# Ruta para empleados
@app.route('/empleados', methods=['GET'])
def empleados():
    usuario = obtener_usuario_actual()
    if not usuario:
        return redirect(url_for('login'))
    if usuario['rol'].lower() != 'colaborador':
        flash('Acceso restringido.')
        return redirect(url_for('login'))

    turno_abierto = False
    fecha_apertura = None
    # Si ya existe un turno abierto en sesión, verificar en la BD.
    if 'turno_id' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        # SEGURIDAD: se verifica que el turno pertenezca al usuario de la sesión
        cur.execute("SELECT * FROM turno WHERE id = %s AND id_usuario = %s AND estado IN ('Abierto', 'abierto')",
                    (session['turno_id'], usuario['id']))
        turno = cur.fetchone()
        cur.close()
        conn.close()
        if turno:
            turno_abierto = True
            fecha_apertura = turno['fecha_apertura']
    if not turno_abierto:
        turno = obtener_turno_abierto_usuario(usuario['id'])
        if turno:
            session['turno_id'] = turno['id']
            turno_abierto = True
            fecha_apertura = turno['fecha_apertura']

    permisos = obtener_permisos_usuario()
    return render_template('empleados.html', turno_abierto=turno_abierto, fecha_apertura=fecha_apertura, permisos=permisos)

# Ruta para panel de habitaciones

# --- CRUD Habitaciones ---
@app.route('/habitaciones', methods=['GET', 'POST'])
def habitaciones():
    # Validar acceso
    acceso_negado = validar_acceso('habitaciones')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        # Registrar nueva habitación
        # SEGURIDAD: validación de longitud (según la BD) y de precio positivo
        numero = leer_texto(request.form.get('numero'), 10)
        tipo = leer_texto(request.form.get('tipo'), 50)
        precio = leer_decimal(request.form.get('precio_estandar'))
        if numero is None or tipo is None or precio is None:
            flash('Datos de habitación inválidos.')
        else:
            cur.execute("INSERT INTO habitacion (numero, tipo, precio_estandar) VALUES (%s, %s, %s)", (numero, tipo, precio))
            conn.commit()
    cur.execute("SELECT * FROM habitacion ORDER BY id")
    habitaciones = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('habitaciones.html', habitaciones=habitaciones)


@app.route('/admin', methods=['GET'])
def admin():
    return render_template('admin.html')

# Crear turno (POST desde empleados.html)
@app.route('/abrir_turno', methods=['POST'])
def abrir_turno():
    usuario = obtener_usuario_actual()
    if not usuario:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    # SEGURIDAD: get_json(silent=True) evita un error 500 si el cuerpo no es JSON
    datos = request.get_json(silent=True) or {}
    base_caja = leer_decimal(datos.get('base_caja'))
    if base_caja is None:
        return jsonify({'ok': False, 'msg': 'Monto inválido'}), 400
    # Insertar turno
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO turno (id_usuario, base_caja, estado, recaudo_total)
        VALUES (%s, %s, 'Abierto', 0)
        RETURNING id, fecha_apertura
    """, (usuario['id'], base_caja))
    turno = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    session['turno_id'] = turno['id']
    fecha_apertura_local = convertir_a_hora_local(turno['fecha_apertura']).strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({'ok': True, 'turno_id': turno['id'], 'fecha_apertura': fecha_apertura_local})

# Cerrar turno (POST desde empleados.html)
@app.route('/cerrar_turno', methods=['POST'])
def cerrar_turno():
    if 'usuario' not in session or 'turno_id' not in session:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    turno_id = session['turno_id']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE turno SET fecha_cierre = CURRENT_TIMESTAMP, estado = 'Cerrado'
        WHERE id = %s
    """, (turno_id,))
    conn.commit()
    cur.close()
    conn.close()
    # SEGURIDAD: se borra toda la sesión, no solo algunas claves
    session.clear()
    return jsonify({'ok': True})

# Logout para Admin (sin registrar turno)
# SEGURIDAD: ahora es POST (con token CSRF). Con GET, cualquier página externa
# podía cerrar la sesión del usuario con una simple etiqueta <img>.
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.')
    return redirect(url_for('login'))

# Cerrar sesión (GET desde header_colaborador.html)
@app.route('/cerrar_sesion', methods=['POST'])
def cerrar_sesion():
    if 'usuario' not in session or 'turno_id' not in session:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    turno_id = session['turno_id']
    datos = request.get_json(silent=True)
    observaciones = ''
    if datos:
        observaciones = datos.get('observaciones', '')
    else:
        observaciones = request.form.get('observaciones', '')
    # SEGURIDAD: límite de longitud para las observaciones
    observaciones = str(observaciones or '').strip()[:1000]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE turno SET fecha_cierre = CURRENT_TIMESTAMP, estado = 'Cerrado', observaciones = %s
        WHERE id = %s
    """, (observaciones, turno_id))
    conn.commit()
    cur.close()
    conn.close()
    session.clear()
    return jsonify({'ok': True})

# --- RUTAS DE TURNOS (deben ir después de la definición de app) ---
# (Mover esto después de la definición de app)

# Panel de administración principal
@app.route('/panel_admin')
def panel_admin():
    permisos = obtener_permisos_usuario()
    es_colaborador = False

    usuario = obtener_usuario_actual()
    if usuario:
        es_colaborador = usuario['rol'].lower() == 'colaborador'

        # Si es Admin, mostrar vista admin_panel.html sin turnos
        if es_admin(usuario):
            return render_template('admin_panel.html', permisos=permisos)

        # Si es Colaborador, verificar turno abierto
        if es_colaborador:
            turno_abierto = False
            fecha_apertura = None

            # Verificar si tiene turno abierto
            if 'turno_id' in session:
                conn = get_db_connection()
                cur = conn.cursor()
                # SEGURIDAD: el turno debe pertenecer al usuario de la sesión
                cur.execute("SELECT * FROM turno WHERE id = %s AND id_usuario = %s AND estado IN ('Abierto', 'abierto')",
                            (session['turno_id'], usuario['id']))
                turno = cur.fetchone()
                cur.close()
                conn.close()
                if turno:
                    turno_abierto = True
                    fecha_apertura = convertir_a_hora_local(turno['fecha_apertura']).strftime('%Y-%m-%d %H:%M:%S')

            if not turno_abierto:
                turno = obtener_turno_abierto_usuario(usuario['id'])
                if turno:
                    session['turno_id'] = turno['id']
                    turno_abierto = True
                    fecha_apertura = convertir_a_hora_local(turno['fecha_apertura']).strftime('%Y-%m-%d %H:%M:%S')

            return render_template('panel_admin.html', permisos=permisos, turno_abierto=turno_abierto,
                                 fecha_apertura=fecha_apertura, es_colaborador=es_colaborador)

    return redirect(url_for('login'))

# Paneles individuales
@app.route('/turnos')
def turnos():
    # Validar acceso
    acceso_negado = validar_acceso('turnos')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Obtener todos los turnos (uniendo con la tabla usuario para ver el nombre)
    cur.execute("""
        SELECT t.*, u.nombres as nombre_usuario
        FROM turno t
        JOIN usuario u ON t.id_usuario = u.id
        ORDER BY t.fecha_apertura DESC
    """)
    todos_los_turnos = cur.fetchall()

    # 2. Obtener solo el último registro
    cur.execute("""
        SELECT t.*, u.nombres as nombre_usuario
        FROM turno t
        JOIN usuario u ON t.id_usuario = u.id
        ORDER BY t.id DESC LIMIT 1
    """)
    ultimo_turno = cur.fetchone()

    # Convertir fechas a hora local de Colombia
    for turno in todos_los_turnos:
        if turno.get('fecha_apertura'):
            turno['fecha_apertura'] = convertir_a_hora_local(turno['fecha_apertura'])
        if turno.get('fecha_cierre'):
            turno['fecha_cierre'] = convertir_a_hora_local(turno['fecha_cierre'])
    if ultimo_turno:
        if ultimo_turno.get('fecha_apertura'):
            ultimo_turno['fecha_apertura'] = convertir_a_hora_local(ultimo_turno['fecha_apertura'])
        if ultimo_turno.get('fecha_cierre'):
            ultimo_turno['fecha_cierre'] = convertir_a_hora_local(ultimo_turno['fecha_cierre'])

    cur.close()
    conn.close()
    return render_template('turnos.html', turnos=todos_los_turnos, ultimo=ultimo_turno)

# --- CRUD Inventario ---
@app.route('/inventario', methods=['GET', 'POST'])
def inventario():
    # Validar acceso
    acceso_negado = validar_acceso('inventario')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        # SEGURIDAD: stock y precios deben ser números no negativos
        nombre = leer_texto(request.form.get('nombre'), 100)
        stock_actual = leer_entero(request.form.get('stock_actual'), minimo=0, maximo=1000000)
        precio_costo = leer_decimal(request.form.get('precio_costo'))
        precio_venta = leer_decimal(request.form.get('precio_venta'))
        stock_minimo = leer_entero(request.form.get('stock_minimo'), minimo=0, maximo=1000000)
        if None in (nombre, stock_actual, precio_costo, precio_venta, stock_minimo):
            flash('Datos de producto inválidos.')
        else:
            cur.execute("INSERT INTO inventario (nombre, stock_actual, precio_costo, precio_venta, stock_minimo) VALUES (%s, %s, %s, %s, %s)",
                (nombre, stock_actual, precio_costo, precio_venta, stock_minimo))
            conn.commit()
    cur.execute("SELECT * FROM inventario ORDER BY id")
    productos = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('inventario.html', productos=productos)


# --- Registro de Ventas ---


# --- Registro de Ventas mejorado ---

# Carrito de productos por habitación en sesión
@app.route('/ventas', methods=['GET', 'POST'])
def ventas():
    # Validar acceso
    acceso_negado = validar_acceso('ventas')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM inventario ORDER BY nombre")
    productos = cur.fetchall()
    cur.execute("SELECT * FROM habitacion ORDER BY numero")
    habitaciones = cur.fetchall()
    usuario_id = None
    if 'usuario' in session:
        cur.execute("SELECT id FROM usuario WHERE correo=%s", (session['usuario'],))
        u = cur.fetchone()
        if u:
            usuario_id = u['id']
    mensaje = None
    # Carrito de productos por habitación
    if 'carrito' not in session:
        session['carrito'] = {}
    carrito = session['carrito']
    if request.method == 'POST':
        # SEGURIDAD: los identificadores deben ser enteros y la cantidad positiva.
        # Antes una cantidad negativa AUMENTABA el stock y restaba del recaudo.
        id_hab_num = leer_entero(request.form.get('id_habitacion'), minimo=1)
        id_habitacion = str(id_hab_num) if id_hab_num else None
        id_producto = leer_entero(request.form.get('id_producto'), minimo=1)
        cantidad = leer_entero(request.form.get('cantidad'), minimo=1, maximo=1000)
        accion = request.form.get('accion')
        if not id_habitacion:
            mensaje = 'Habitación inválida.'
        elif accion == 'agregar_producto' and id_producto and cantidad:
            # Agregar producto al carrito
            if id_habitacion not in carrito:
                carrito[id_habitacion] = []
            carrito[id_habitacion].append({'id_producto': id_producto, 'cantidad': cantidad})
            session['carrito'] = carrito
            mensaje = 'Producto agregado al carrito.'
        elif accion == 'registrar_venta' and usuario_id:
            # Registrar venta solo al ocupar
            productos_hab = carrito.get(id_habitacion, [])
            stock_ok = True
            for item in productos_hab:
                cur.execute("SELECT precio_venta, stock_actual FROM inventario WHERE id = %s", (item['id_producto'],))
                prod = cur.fetchone()
                if not prod or prod['stock_actual'] < item['cantidad']:
                    mensaje = 'Stock insuficiente para algún producto.'
                    stock_ok = False
                    break
            if stock_ok:
                total = 0
                for item in productos_hab:
                    cur.execute("SELECT precio_venta FROM inventario WHERE id = %s", (item['id_producto'],))
                    prod = cur.fetchone()
                    total += float(prod['precio_venta']) * item['cantidad']
                # Sumar valor de la habitación
                cur.execute("SELECT precio_estandar FROM habitacion WHERE id = %s", (id_habitacion,))
                hab = cur.fetchone()
                if hab:
                    total += float(hab['precio_estandar'])
                for item in productos_hab:
                    cur.execute("SELECT precio_venta FROM inventario WHERE id = %s", (item['id_producto'],))
                    prod = cur.fetchone()
                    total_pago = float(prod['precio_venta']) * item['cantidad']
                    cur.execute("INSERT INTO venta (id_usuario, id_habitacion, id_producto, cantidad, total_pago) VALUES (%s, %s, %s, %s, %s)",
                        (usuario_id, id_habitacion, item['id_producto'], item['cantidad'], total_pago))
                    cur.execute("UPDATE inventario SET stock_actual = stock_actual - %s WHERE id = %s", (item['cantidad'], item['id_producto']))
                # Actualizar recaudo total del turno si es colaborador con turno abierto
                if 'turno_id' in session and session.get('rol', '').lower() == 'colaborador':
                    cur.execute("UPDATE turno SET recaudo_total = COALESCE(recaudo_total, 0) + %s WHERE id = %s", (total, session['turno_id']))
                conn.commit()
                mensaje = f'Venta registrada. Total: ${total}'
                carrito.pop(id_habitacion, None)
                session['carrito'] = carrito
        else:
            mensaje = 'Acción no válida o datos incompletos.'
    # Mostrar ventas
    cur.execute("""
        SELECT v.*, u.nombres as usuario, h.numero as habitacion, i.nombre as producto
        FROM venta v
        JOIN usuario u ON v.id_usuario = u.id
        LEFT JOIN habitacion h ON v.id_habitacion = h.id
        JOIN inventario i ON v.id_producto = i.id
        ORDER BY v.fecha_venta DESC
    """)
    ventas = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('ventas.html', productos=productos, habitaciones=habitaciones, ventas=ventas, mensaje=mensaje, carrito=carrito)

# =====================================================================
# MÓDULO: Gestión de nómina
# ---------------------------------------------------------------------
# Cada colaboradora tiene una "ficha" (cargo, EPS, ARL, pensión, C.C.F.,
# salario...) y por cada quincena se genera una "liquidación" con sus
# devengados, deducciones y el valor neto a pagar.
#
# SEGURIDAD: la ficha y los valores de cada liquidación se guardan CIFRADOS
# en la BD con Fernet (AES-128 + HMAC-SHA256). Quien abra las tablas en Neon
# solo ve texto ilegible, y cualquier modificación manual del texto cifrado
# se detecta. La clave está en la variable de entorno NOMINA_CLAVE (.env /
# Render), nunca en el código. Si la clave se pierde, los datos de nómina NO
# se pueden recuperar: guárdala en un lugar seguro.
#
# Resumen de lo que se agregó para este módulo:
#   - Tablas nuevas en la BD: nomina_ficha y nomina_liquidacion.
#   - Funciones de cifrado: cifrar_nomina() y descifrar_nomina().
#   - Cálculo de la quincena: calcular_liquidacion().
#   - Rutas: /nomina (página principal), /nomina/ficha (guardar ficha),
#     /nomina/liquidar (crear o editar liquidación), /nomina/comprobante/<id>
#     (comprobante imprimible) y /nomina/liquidacion/<id>/<accion> (pagar o
#     eliminar).
# =====================================================================

# Crea el objeto que cifra y descifra usando la clave NOMINA_CLAVE del .env.
# Si la clave no existe o está mal escrita devuelve None, y el módulo de
# nómina se muestra deshabilitado en lugar de guardar datos sin cifrar.
def obtener_cifrador_nomina():
    clave = os.environ.get('NOMINA_CLAVE')
    if not clave:
        app.logger.warning('NOMINA_CLAVE no definida: el módulo de nómina queda deshabilitado.')
        return None
    try:
        return Fernet(clave.encode('ascii'))
    except (ValueError, UnicodeEncodeError):
        app.logger.error('NOMINA_CLAVE tiene un formato inválido: el módulo de nómina queda deshabilitado.')
        return None

# Se crea una sola vez al arrancar la app (por eso hay que reiniciar si
# cambia la clave en el .env)
CIFRADOR_NOMINA = obtener_cifrador_nomina()

# Convierte un diccionario (ficha o liquidación) en texto cifrado listo para
# guardar en la BD. Ejemplo de resultado: "gAAAAABq3pR-B1hwiVFG..."
def cifrar_nomina(datos, id_usuario):
    # SEGURIDAD: se guarda dentro del cifrado a quién pertenece el registro,
    # para poder comprobarlo al descifrar
    contenido = dict(datos, _id_usuario=id_usuario)
    return CIFRADOR_NOMINA.encrypt(json.dumps(contenido).encode('utf-8')).decode('ascii')

# Hace lo contrario: recibe el texto cifrado de la BD y devuelve el
# diccionario original. Devuelve None si el texto fue alterado, si la clave
# no es la misma con la que se cifró, o si el registro es de otra persona.
def descifrar_nomina(texto, id_usuario):
    try:
        datos = json.loads(CIFRADOR_NOMINA.decrypt(texto.encode('ascii')))
    except (InvalidToken, ValueError):
        app.logger.error('Registro de nómina ilegible o alterado (usuario %s).', id_usuario)
        return None
    # SEGURIDAD: si alguien copia en la BD el registro cifrado de una persona
    # a otra, el dueño guardado dentro no coincide y el registro se rechaza
    if datos.pop('_id_usuario', None) != id_usuario:
        app.logger.error('Registro de nómina con dueño incorrecto (usuario %s).', id_usuario)
        return None
    return datos

# Indica si ya se revisó que existan las tablas de nómina (se hace una sola
# vez por cada arranque de la app, no en cada clic)
_tablas_nomina_listas = False

# Crea las tablas de nómina en Neon si todavía no existen ("IF NOT EXISTS"
# hace que no se borre ni se duplique nada si ya están creadas).
#   - nomina_ficha: una fila por colaboradora con sus datos laborales
#     (cargo, EPS, ARL, pensión, C.C.F., salario...) en "datos_cifrados".
#   - nomina_liquidacion: una fila por cada quincena liquidada. Las fechas y
#     el estado (Borrador / Pagada) quedan visibles para poder ordenar y
#     filtrar; los valores en pesos van en "datos_cifrados".
#     UNIQUE (id_usuario, periodo_inicio) impide liquidar dos veces la misma
#     quincena a la misma persona.
def asegurar_tablas_nomina(conn):
    global _tablas_nomina_listas
    if _tablas_nomina_listas:
        return
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nomina_ficha (
            id_usuario INTEGER PRIMARY KEY REFERENCES usuario(id) ON DELETE CASCADE,
            datos_cifrados TEXT NOT NULL,
            actualizado_por INTEGER REFERENCES usuario(id),
            fecha_actualizacion TIMESTAMP NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS nomina_liquidacion (
            id SERIAL PRIMARY KEY,
            id_usuario INTEGER NOT NULL REFERENCES usuario(id),
            periodo_inicio DATE NOT NULL,
            periodo_fin DATE NOT NULL,
            estado VARCHAR(20) NOT NULL DEFAULT 'Borrador',
            datos_cifrados TEXT NOT NULL,
            creado_por INTEGER REFERENCES usuario(id),
            fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW(),
            fecha_pago TIMESTAMP,
            UNIQUE (id_usuario, periodo_inicio)
        );
    """)
    conn.commit()
    cur.close()
    _tablas_nomina_listas = True

# --- Valores fijos de la nómina (se cambian aquí si cambia la ley o la empresa) ---
EMPRESA_NOMINA = 'SAN ANDRES SUITE UBATE'  # Nombre que sale en el encabezado del comprobante
PORCENTAJE_SALUD = Decimal('0.04')    # 4% que se descuenta para salud
PORCENTAJE_PENSION = Decimal('0.04')  # 4% que se descuenta para pensión
DIAS_MES_NOMINA = Decimal('30')       # En nómina el mes siempre se cuenta de 30 días
MAX_CONCEPTOS_EXTRA = 5               # Cuántos pagos/descuentos adicionales se permiten por quincena
ESTADOS_LIQUIDACION = ('Borrador', 'Pagada')
# Nombres de los meses para escribir el periodo ("01 al 15 Septiembre del 2026")
MESES = ('Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio', 'Julio',
         'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre')
# Campos de texto de la ficha y su largo máximo
CAMPOS_FICHA_TEXTO = {'cargo': 100, 'sede': 60, 'eps': 60, 'arl': 60, 'pension': 60, 'ccf': 60}
# Campos de la ficha que son valores en pesos
CAMPOS_FICHA_DINERO = ('salario', 'subsidio_transporte', 'recargo_nocturno_hora')
# SEGURIDAD: tope para cualquier valor en pesos ($100 millones), evita que un
# valor absurdo digitado por error o a propósito llegue a la nómina
MAXIMO_DINERO = Decimal('100000000')

# SEGURIDAD: convierte el texto "2026-09-01" en una fecha. Devuelve None si
# no es una fecha válida o si el año está fuera de un rango razonable.
def leer_fecha(valor):
    try:
        fecha = date.fromisoformat((valor or '').strip())
    except ValueError:
        return None
    return fecha if 2000 <= fecha.year <= 2100 else None

# Redondea al peso más cercano: 875452.5 -> 875453
def redondear_peso(valor):
    return Decimal(valor).quantize(Decimal('1'), rounding=ROUND_HALF_UP)

# Convierte un número a texto con 2 decimales para guardarlo dentro del JSON
# cifrado ("875452.50"). Se usa Decimal y no float para no perder centavos.
def a_texto(valor):
    # Los valores se guardan con 2 decimales y se redondean al peso solo al mostrarlos
    return str(Decimal(valor).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))

# Filtro para las plantillas: {{ valor|pesos }} muestra 1750905 como "1.750.905"
@app.template_filter('pesos')
def formato_pesos(valor):
    if valor in (None, ''):
        return ''
    return f"{int(redondear_peso(valor)):,}".replace(',', '.')

# Arma el texto del periodo para el comprobante:
#   mismo mes   -> "01 al 15 Septiembre del 2026"
#   dos meses   -> "16 Septiembre al 15 Octubre del 2026"
def nombre_periodo(inicio, fin):
    if (inicio.year, inicio.month) == (fin.year, fin.month):
        return f"{inicio.day:02d} al {fin.day:02d} {MESES[fin.month - 1]} del {fin.year}"
    return f"{inicio.day:02d} {MESES[inicio.month - 1]} al {fin.day:02d} {MESES[fin.month - 1]} del {fin.year}"

# SEGURIDAD: lee y valida el formulario "Ficha de nómina". Cada campo se
# revisa (largo máximo, números válidos, no negativos, fecha real). Si algún
# campo no es válido devuelve None y no se guarda nada. El cargo es el único
# texto obligatorio.
def leer_ficha_formulario(form):
    ficha = {campo: leer_texto(form.get(campo), largo, requerido=(campo == 'cargo'))
             for campo, largo in CAMPOS_FICHA_TEXTO.items()}
    for campo in CAMPOS_FICHA_DINERO:
        valor = leer_decimal(form.get(campo) or '0', maximo=MAXIMO_DINERO)
        ficha[campo] = a_texto(valor) if valor is not None else None
    ficha['horas_semanales'] = leer_entero(form.get('horas_semanales'), minimo=1, maximo=60)
    # La fecha de ingreso es opcional: vacía se guarda como '' y una fecha
    # mal escrita se marca como inválida (None)
    if form.get('fecha_ingreso'):
        fecha = leer_fecha(form.get('fecha_ingreso'))
        ficha['fecha_ingreso'] = fecha.isoformat() if fecha else None
    else:
        ficha['fecha_ingreso'] = ''
    return None if None in ficha.values() else ficha

# Lee las filas de "Otros pagos" (prefijo 'extra_dev') u "Otros descuentos"
# (prefijo 'extra_ded'). Cada fila trae un concepto y un valor; las filas
# que se dejaron vacías se ignoran. Devuelve None si alguna fila está a
# medias o tiene un valor inválido, y nunca más de MAX_CONCEPTOS_EXTRA filas.
def leer_conceptos_extra(form, prefijo):
    conceptos = []
    for concepto, valor in zip(form.getlist(prefijo + '_concepto'), form.getlist(prefijo + '_valor')):
        concepto = (concepto or '').strip()
        if not concepto and not (valor or '').strip():
            continue
        concepto = leer_texto(concepto, 60)
        valor = leer_decimal(valor, maximo=MAXIMO_DINERO)
        if concepto is None or valor is None:
            return None
        conceptos.append({'concepto': concepto, 'valor': a_texto(valor)})
    return conceptos[:MAX_CONCEPTOS_EXTRA]

# SEGURIDAD: lee y valida el formulario "Liquidar quincena": periodo, días,
# horas, recargo nocturno, préstamos, ausentismo, no justificado, ajuste,
# nota y los pagos/descuentos adicionales. Devuelve el diccionario "entrada"
# (que también se guarda para poder editar el borrador después) y una lista
# de mensajes de error para mostrar al usuario.
def leer_entrada_liquidacion(form):
    """Devuelve (entrada, errores) con los datos digitados para liquidar."""
    errores = []
    # El periodo debe tener fechas válidas, la final no puede ser anterior a
    # la inicial y no puede durar más de un mes
    inicio = leer_fecha(form.get('periodo_inicio'))
    fin = leer_fecha(form.get('periodo_fin'))
    if not inicio or not fin or fin < inicio or (fin - inicio).days > 31:
        errores.append('Periodo inválido: la fecha final debe ser posterior a la inicial y el periodo no puede superar un mes.')
    entrada = {
        'periodo_inicio': inicio.isoformat() if inicio else None,
        'periodo_fin': fin.isoformat() if fin else None,
        'dias': leer_entero(form.get('dias'), minimo=0, maximo=31),
        'dias_transporte': leer_entero(form.get('dias_transporte'), minimo=0, maximo=31),
        'horas': leer_entero(form.get('horas') or '0', minimo=0, maximo=400),
        'horas_nocturnas': leer_decimal(form.get('horas_nocturnas') or '0', maximo=Decimal('400')),
        'prestamos': leer_decimal(form.get('prestamos') or '0', maximo=MAXIMO_DINERO),
        'ausentismo': leer_decimal(form.get('ausentismo') or '0', maximo=MAXIMO_DINERO),
        'no_justificado': leer_decimal(form.get('no_justificado') or '0', maximo=MAXIMO_DINERO),
        'ajuste': leer_decimal(form.get('ajuste') or '0', minimo=Decimal('-1000000'), maximo=Decimal('1000000')),
        'redondear': form.get('redondear') == '1',
        'nota': leer_texto(form.get('nota'), 300, requerido=False),
        'devengados_extra': leer_conceptos_extra(form, 'extra_dev'),
        'deducciones_extra': leer_conceptos_extra(form, 'extra_ded'),
    }
    # Las funciones leer_* devuelven None cuando un valor no es válido; si
    # quedó alguno así, no se liquida (el periodo ya se revisó arriba)
    campos_invalidos = [k for k, v in entrada.items() if v is None and k not in ('periodo_inicio', 'periodo_fin')]
    if campos_invalidos:
        errores.append('Revisa los valores digitados: hay campos vacíos, negativos o demasiado grandes.')
    # Los valores en pesos se pasan a texto para poder guardarlos en JSON
    for campo in ('horas_nocturnas', 'prestamos', 'ausentismo', 'no_justificado', 'ajuste'):
        if entrada[campo] is not None:
            entrada[campo] = a_texto(entrada[campo])
    return entrada, errores

def calcular_liquidacion(ficha, entrada):
    """Calcula devengados, deducciones y neto igual que el comprobante en Excel."""
    # Ejemplo con el comprobante de septiembre (salario $1.750.905, 15 días):
    #   Salario base      = 1.750.905 / 30 x 15 = $875.453
    #   Auxilio transporte =  249.095 / 30 x 15 = $124.548
    #   Recargo nocturno  = 2.918 x 105 horas   = $306.390
    #   Salud y pensión   = 4% de 875.453       = $35.018 cada una
    #   Ajuste de nómina  = lo que falta para que el neto sea $1.237.000 ($646)
    salario = Decimal(ficha['salario'])
    dias = Decimal(entrada['dias'])
    salario_periodo = salario / DIAS_MES_NOMINA * dias

    # --- DEVENGADO: todo lo que se le paga a la colaboradora ---
    devengados = [
        {'concepto': 'Salario Base', 'dias': entrada['dias'], 'horas': entrada['horas'], 'valor': salario_periodo},
        {'concepto': 'Auxilio Transporte', 'dias': entrada['dias_transporte'], 'horas': None,
         'valor': Decimal(ficha['subsidio_transporte']) / DIAS_MES_NOMINA * entrada['dias_transporte']},
    ]
    # El recargo nocturno solo aparece si hubo horas nocturnas en la quincena
    horas_nocturnas = Decimal(entrada['horas_nocturnas'])
    if horas_nocturnas:
        devengados.append({'concepto': 'Recargo Nocturno', 'dias': None, 'horas': str(horas_nocturnas.normalize()),
                           'valor': Decimal(ficha['recargo_nocturno_hora']) * horas_nocturnas})
    # Pagos adicionales digitados (bonificaciones, horas extra...)
    for extra in entrada['devengados_extra']:
        devengados.append({'concepto': extra['concepto'], 'dias': None, 'horas': None, 'valor': Decimal(extra['valor'])})

    # --- DEDUCCIONES: todo lo que se le descuenta ---
    # Salud y pensión se calculan sobre el salario del periodo, como en el comprobante
    deducciones = [
        {'concepto': 'Salud', 'porcentaje': '4%', 'valor': salario_periodo * PORCENTAJE_SALUD},
        {'concepto': 'Pension', 'porcentaje': '4%', 'valor': salario_periodo * PORCENTAJE_PENSION},
    ]
    # Préstamos, ausentismo y no justificado solo aparecen si tienen valor
    for campo, concepto in (('prestamos', 'Prestamos'), ('ausentismo', 'Ausentismo'), ('no_justificado', 'No Justificado')):
        if Decimal(entrada[campo]):
            deducciones.append({'concepto': concepto, 'porcentaje': None, 'valor': Decimal(entrada[campo])})
    # Descuentos adicionales digitados
    for extra in entrada['deducciones_extra']:
        deducciones.append({'concepto': extra['concepto'], 'porcentaje': None, 'valor': Decimal(extra['valor'])})

    # --- TOTALES Y AJUSTE DE NÓMINA ---
    total_deducciones = sum(d['valor'] for d in deducciones)
    subtotal = sum(d['valor'] for d in devengados)
    # Con "redondear" marcado, el ajuste se calcula solo; si no, se usa el
    # ajuste manual que se digitó (puede ser positivo o negativo)
    if entrada['redondear']:
        # El ajuste lleva el neto al siguiente múltiplo de $1.000
        neto_sin_ajuste = subtotal - total_deducciones
        ajuste = (neto_sin_ajuste / 1000).to_integral_value(rounding=ROUND_CEILING) * 1000 - neto_sin_ajuste
    else:
        ajuste = Decimal(entrada['ajuste'])
    if ajuste:
        devengados.append({'concepto': 'Ajuste Nomina', 'dias': None, 'horas': None, 'valor': ajuste})
    total_devengado = subtotal + ajuste

    # Se pasan los valores a texto para guardarlos cifrados en la BD
    for linea in devengados + deducciones:
        linea['valor'] = a_texto(linea['valor'])
    return {
        'devengados': devengados,
        'deducciones': deducciones,
        'total_devengado': a_texto(total_devengado),
        'total_deducciones': a_texto(total_deducciones),
        'neto': a_texto(total_devengado - total_deducciones),
    }

def puede_modificar_nomina(usuario_sesion, destino):
    # SEGURIDAD: un colaborador con permiso de nómina no puede cambiar su propio
    # salario ni sus pagos, ni los de un administrador
    return es_admin(usuario_sesion) or (destino['id'] != usuario_sesion['id'] and not es_admin(destino))

# SEGURIDAD: revisión que hacen todas las rutas de nómina que modifican o
# muestran datos de pago: el usuario debe tener el permiso "nomina" y la
# clave de cifrado debe estar configurada.
def preparar_nomina():
    """Valida acceso y clave de cifrado. Devuelve (respuesta_error, usuario_sesion)."""
    acceso_negado = validar_acceso('nomina')
    if acceso_negado:
        return acceso_negado, None
    if CIFRADOR_NOMINA is None:
        flash('El módulo de nómina no está configurado: falta la clave NOMINA_CLAVE.')
        return redirect(url_for('nomina')), None
    return None, obtener_usuario_actual()

# --- PANEL: Gestión de nómina (página principal) ---
# Muestra la tabla de colaboradoras con su ficha, los formularios para
# configurar la ficha y liquidar, y el historial de liquidaciones.
@app.route('/nomina')
def nomina():
    # Validar acceso
    acceso_negado = validar_acceso('nomina')
    if acceso_negado:
        return acceso_negado
    # Sin clave de cifrado se muestra un aviso en vez de los datos
    if CIFRADOR_NOMINA is None:
        return render_template('nomina.html', sin_clave=True)

    conn = get_db_connection()
    asegurar_tablas_nomina(conn)
    cur = conn.cursor()
    # Usuarias activas junto con su ficha (si ya tienen una). Se descifra cada
    # ficha aquí en el servidor; en la BD siguen cifradas.
    cur.execute("""SELECT u.id, u.documento, u.nombres, u.apellidos, u.rol, f.datos_cifrados
                   FROM usuario u LEFT JOIN nomina_ficha f ON f.id_usuario = u.id
                   WHERE u.estado = 'Activo' ORDER BY u.nombres, u.apellidos""")
    empleados = []
    for fila in cur.fetchall():
        ficha = descifrar_nomina(fila['datos_cifrados'], fila['id']) if fila['datos_cifrados'] else None
        empleados.append({'id': fila['id'], 'documento': fila['documento'],
                          'nombre': f"{fila['nombres']} {fila['apellidos']}", 'rol': fila['rol'], 'ficha': ficha})

    # Historial: las 200 liquidaciones más recientes, con sus totales descifrados
    cur.execute("""SELECT l.id, l.id_usuario, l.periodo_inicio, l.periodo_fin, l.estado, l.datos_cifrados,
                          l.fecha_pago, u.nombres, u.apellidos
                   FROM nomina_liquidacion l JOIN usuario u ON u.id = l.id_usuario
                   ORDER BY l.periodo_inicio DESC, u.nombres LIMIT 200""")
    liquidaciones = []
    for fila in cur.fetchall():
        datos = descifrar_nomina(fila['datos_cifrados'], fila['id_usuario'])
        liquidaciones.append({'id': fila['id'], 'id_usuario': fila['id_usuario'], 'estado': fila['estado'],
                              'nombre': f"{fila['nombres']} {fila['apellidos']}",
                              'periodo': nombre_periodo(fila['periodo_inicio'], fila['periodo_fin']),
                              'fecha_pago': convertir_a_hora_local(fila['fecha_pago']), 'datos': datos})
    cur.close()
    conn.close()
    return render_template('nomina.html', empleados=empleados, liquidaciones=liquidaciones,
                           max_extra=MAX_CONCEPTOS_EXTRA, hoy=datetime.now(LOCAL_ZONE).date())

# --- NÓMINA: Guardar ficha de una colaboradora ---
# Recibe el formulario "Ficha de nómina", lo valida, lo cifra y lo guarda.
# Si la colaboradora ya tenía ficha, la reemplaza (ON CONFLICT ... DO UPDATE).
@app.route('/nomina/ficha', methods=['POST'])
def nomina_ficha():
    respuesta, usuario_sesion = preparar_nomina()
    if respuesta:
        return respuesta
    id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1)
    ficha = leer_ficha_formulario(request.form)
    conn = get_db_connection()
    asegurar_tablas_nomina(conn)
    cur = conn.cursor()
    destino = None
    if id_usuario:
        cur.execute("SELECT id, rol FROM usuario WHERE id=%s", (id_usuario,))
        destino = cur.fetchone()
    if not destino:
        flash('Colaboradora inválida.')
    elif not puede_modificar_nomina(usuario_sesion, destino):
        flash('No puedes modificar la ficha de nómina de este usuario.')
    elif ficha is None:
        flash('Revisa la ficha: el cargo es obligatorio y los valores deben ser números válidos.')
    else:
        cur.execute("""INSERT INTO nomina_ficha (id_usuario, datos_cifrados, actualizado_por, fecha_actualizacion)
                       VALUES (%s, %s, %s, NOW())
                       ON CONFLICT (id_usuario) DO UPDATE SET datos_cifrados = EXCLUDED.datos_cifrados,
                           actualizado_por = EXCLUDED.actualizado_por, fecha_actualizacion = NOW()""",
                    (id_usuario, cifrar_nomina(ficha, id_usuario), usuario_sesion['id']))
        conn.commit()
        # SEGURIDAD: queda registro de quién cambió la ficha (sin los valores)
        app.logger.info('Ficha de nómina del usuario %s actualizada por %s', id_usuario, usuario_sesion['correo'])
        flash('Ficha de nómina guardada.')
    cur.close()
    conn.close()
    return redirect(url_for('nomina'))

# --- NÓMINA: Crear o editar una liquidación de quincena ---
# Si el formulario trae "id_liquidacion" se edita ese borrador; si no, se
# crea una liquidación nueva. Siempre queda en estado "Borrador" y al final
# se abre su comprobante para revisarlo.
@app.route('/nomina/liquidar', methods=['POST'])
def nomina_liquidar():
    respuesta, usuario_sesion = preparar_nomina()
    if respuesta:
        return respuesta
    id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1)
    id_liquidacion = leer_entero(request.form.get('id_liquidacion'), minimo=1) if request.form.get('id_liquidacion') else None
    entrada, errores = leer_entrada_liquidacion(request.form)

    conn = get_db_connection()
    asegurar_tablas_nomina(conn)
    cur = conn.cursor()
    # Paso 1: la colaboradora debe existir, el usuario debe poder modificarla
    # y ella debe tener una ficha (de ahí salen el salario, auxilio, etc.)
    destino = ficha = None
    if id_usuario:
        cur.execute("""SELECT u.id, u.rol, f.datos_cifrados FROM usuario u
                       LEFT JOIN nomina_ficha f ON f.id_usuario = u.id WHERE u.id=%s""", (id_usuario,))
        destino = cur.fetchone()
    if not destino:
        errores.insert(0, 'Colaboradora inválida.')
    elif not puede_modificar_nomina(usuario_sesion, destino):
        errores.insert(0, 'No puedes liquidar la nómina de este usuario.')
    elif not destino['datos_cifrados'] or not (ficha := descifrar_nomina(destino['datos_cifrados'], id_usuario)):
        errores.insert(0, 'Primero configura la ficha de nómina de esta colaboradora.')

    # Paso 2: si se está editando, el borrador debe existir, ser de la misma
    # colaboradora y no estar pagado (lo pagado no se puede cambiar)
    anterior = None
    if not errores and id_liquidacion:
        cur.execute("SELECT id, id_usuario, estado FROM nomina_liquidacion WHERE id=%s", (id_liquidacion,))
        anterior = cur.fetchone()
        if not anterior or anterior['id_usuario'] != id_usuario:
            errores.append('La liquidación a editar no existe.')
        elif anterior['estado'] != 'Borrador':
            errores.append('Una liquidación pagada no se puede modificar.')
    # Paso 3: no puede haber otra liquidación de la misma persona que empiece
    # el mismo día (evita pagar dos veces la misma quincena)
    if not errores:
        cur.execute("SELECT id FROM nomina_liquidacion WHERE id_usuario=%s AND periodo_inicio=%s AND id <> %s",
                    (id_usuario, entrada['periodo_inicio'], id_liquidacion or 0))
        if cur.fetchone():
            errores.append('Esta colaboradora ya tiene una liquidación que empieza en esa fecha.')

    # Paso 4: calcular la quincena; el neto no puede quedar negativo
    calculo = None
    if not errores:
        calculo = calcular_liquidacion(ficha, entrada)
        if Decimal(calculo['neto']) < 0:
            errores.append('Las deducciones superan lo devengado: el neto no puede ser negativo.')
    if errores:
        cur.close()
        conn.close()
        flash(' '.join(errores))
        return redirect(url_for('nomina'))

    # Paso 5: cifrar y guardar.
    # Se guarda una copia de la ficha para que el comprobante no cambie si luego se edita la ficha
    datos = dict(calculo, ficha=ficha, entrada=entrada)
    cifrado = cifrar_nomina(datos, id_usuario)
    # "AND estado='Borrador'" es una segunda protección: aunque algo fallara
    # arriba, la BD nunca modifica una liquidación pagada
    if anterior:
        cur.execute("""UPDATE nomina_liquidacion SET periodo_inicio=%s, periodo_fin=%s, datos_cifrados=%s
                       WHERE id=%s AND estado='Borrador'""",
                    (entrada['periodo_inicio'], entrada['periodo_fin'], cifrado, id_liquidacion))
    else:
        cur.execute("""INSERT INTO nomina_liquidacion (id_usuario, periodo_inicio, periodo_fin, datos_cifrados, creado_por)
                       VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                    (id_usuario, entrada['periodo_inicio'], entrada['periodo_fin'], cifrado, usuario_sesion['id']))
        id_liquidacion = cur.fetchone()['id']
    conn.commit()
    cur.close()
    conn.close()
    app.logger.info('Liquidación %s del usuario %s guardada por %s', id_liquidacion, id_usuario, usuario_sesion['correo'])
    flash('Liquidación guardada como borrador. Revísala y márcala como pagada cuando se haga el pago.')
    return redirect(url_for('nomina_comprobante', id_liquidacion=id_liquidacion))

# Busca una liquidación junto con el nombre y documento de la colaboradora
def obtener_liquidacion(cur, id_liquidacion):
    cur.execute("""SELECT l.*, u.documento, u.nombres, u.apellidos, u.rol
                   FROM nomina_liquidacion l JOIN usuario u ON u.id = l.id_usuario WHERE l.id=%s""", (id_liquidacion,))
    return cur.fetchone()

# --- NÓMINA: Comprobante de pago imprimible ---
# Descifra la liquidación y la muestra con el mismo formato del comprobante
# en Excel (plantilla nomina_comprobante.html), lista para imprimir o PDF.
@app.route('/nomina/comprobante/<int:id_liquidacion>')
def nomina_comprobante(id_liquidacion):
    respuesta, _ = preparar_nomina()
    if respuesta:
        return respuesta
    conn = get_db_connection()
    asegurar_tablas_nomina(conn)
    cur = conn.cursor()
    liquidacion = obtener_liquidacion(cur, id_liquidacion)
    cur.close()
    conn.close()
    if not liquidacion:
        abort(404)
    datos = descifrar_nomina(liquidacion['datos_cifrados'], liquidacion['id_usuario'])
    if datos is None:
        flash('No se pudo leer esta liquidación: los datos están dañados o la clave NOMINA_CLAVE cambió.')
        return redirect(url_for('nomina'))
    inicio, fin = liquidacion['periodo_inicio'], liquidacion['periodo_fin']
    # Filas de la tabla "LIQUIDACION": las que hagan falta, mínimo 5 como en el Excel.
    # El título dice "1 Quincena" si el periodo empieza entre el 1 y el 15.
    filas = max(len(datos['devengados']), len(datos['deducciones']), 5)
    return render_template('nomina_comprobante.html', l=liquidacion, d=datos, f=datos['ficha'],
                           empresa=EMPRESA_NOMINA, periodo=nombre_periodo(inicio, fin),
                           titulo=f"Comprobante Nomina {1 if inicio.day <= 15 else 2} Quincena {MESES[inicio.month - 1]}",
                           filas=filas, fecha_pago=convertir_a_hora_local(liquidacion['fecha_pago']))

# --- NÓMINA: Marcar como pagada o eliminar una liquidación ---
# Solo se puede hacer sobre un "Borrador". Una vez pagada, la liquidación
# queda bloqueada para siempre (no se edita ni se borra) como respaldo.
@app.route('/nomina/liquidacion/<int:id_liquidacion>/<accion>', methods=['POST'])
def nomina_accion(id_liquidacion, accion):
    respuesta, usuario_sesion = preparar_nomina()
    if respuesta:
        return respuesta
    # SEGURIDAD: solo se aceptan estas dos acciones
    if accion not in ('pagar', 'eliminar'):
        abort(404)
    conn = get_db_connection()
    asegurar_tablas_nomina(conn)
    cur = conn.cursor()
    liquidacion = obtener_liquidacion(cur, id_liquidacion)
    destino = {'id': liquidacion['id_usuario'], 'rol': liquidacion['rol']} if liquidacion else None
    if not liquidacion:
        flash('La liquidación no existe.')
    elif not puede_modificar_nomina(usuario_sesion, destino):
        flash('No puedes modificar la nómina de este usuario.')
    elif liquidacion['estado'] != 'Borrador':
        flash('La liquidación ya está pagada y no se puede modificar.')
    elif accion == 'pagar':
        cur.execute("UPDATE nomina_liquidacion SET estado='Pagada', fecha_pago=NOW() WHERE id=%s", (id_liquidacion,))
        conn.commit()
        flash('Liquidación marcada como pagada.')
    else:
        cur.execute("DELETE FROM nomina_liquidacion WHERE id=%s AND estado='Borrador'", (id_liquidacion,))
        conn.commit()
        flash('Borrador de liquidación eliminado.')
    # SEGURIDAD: queda registro de quién intentó pagar o eliminar
    if liquidacion:
        app.logger.info('Liquidación %s: acción "%s" por %s', id_liquidacion, accion, usuario_sesion['correo'])
    cur.close()
    conn.close()
    return redirect(url_for('nomina'))

@app.route('/api/habitacion_estado/<int:hab_id>', methods=['POST'])
def api_habitacion_estado(hab_id):
    # SEGURIDAD: esta API no tenía ninguna validación: cualquier persona, sin
    # iniciar sesión, podía cambiar el estado de las habitaciones.
    if not (tiene_permiso('ventas') or tiene_permiso('habitaciones')):
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    data = request.get_json(silent=True) or {}
    estado = data.get('estado')
    tiempo = data.get('tiempo')
    # SEGURIDAD: solo se aceptan los estados y tiempos conocidos
    if estado not in ESTADOS_HABITACION or (tiempo and tiempo not in TIEMPOS_HABITACION):
        return jsonify({'ok': False, 'msg': 'Estado o tiempo inválido'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    if tiempo:
        cur.execute("UPDATE habitacion SET estado=%s, tiempo=%s WHERE id=%s", (estado, tiempo, hab_id))
    else:
        cur.execute("UPDATE habitacion SET estado=%s, tiempo=NULL WHERE id=%s", (estado, hab_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# SEGURIDAD: columnas de usuario que se envían a las plantillas. Se excluye
# "contrasena" para que el hash nunca llegue al HTML del navegador.
COLUMNAS_USUARIO_PUBLICAS = "id, documento, nombres, apellidos, rol, celular, correo, estado, funcion, permisos"

# --- PANEL: Crear usuario ---
@app.route('/usuarios', methods=['GET', 'POST'])
def usuarios():
    # Validar acceso
    acceso_negado = validar_acceso('usuarios')
    if acceso_negado:
        return acceso_negado

    usuario_sesion = obtener_usuario_actual()
    conn = get_db_connection()
    cur = conn.cursor()
    mensaje = None
    if request.method == 'POST':
        id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1) if request.form.get('id_usuario') else None
        # SEGURIDAD: validación de cada campo según los límites de la BD
        documento = leer_texto(request.form.get('documento'), 20)
        nombres = leer_texto(request.form.get('nombres'), 100)
        apellidos = leer_texto(request.form.get('apellidos'), 100)
        rol = (request.form.get('rol') or '').strip().lower()
        celular = leer_texto(request.form.get('celular'), 20, requerido=False)
        correo = leer_texto(request.form.get('correo'), 100)
        contrasena = request.form.get('contrasena') or ''
        estado = request.form.get('estado') or 'Activo'
        funcion = leer_texto(request.form.get('funcion'), 200, requerido=False)

        usuario_actual = None
        if id_usuario:
            cur.execute("SELECT permisos, rol FROM usuario WHERE id=%s", (id_usuario,))
            usuario_actual = cur.fetchone()

        errores = []
        if request.form.get('id_usuario') and not usuario_actual:
            errores.append('El usuario a editar no existe.')
        if None in (documento, nombres, apellidos, celular, funcion):
            errores.append('Revisa los campos: hay datos vacíos o demasiado largos.')
        if correo is None or not REGEX_CORREO.match(correo):
            errores.append('Correo inválido.')
        if rol not in ROLES_VALIDOS:
            errores.append('Rol inválido.')
        if estado not in ESTADOS_USUARIO:
            errores.append('Estado inválido.')
        # Al crear, la contraseña es obligatoria; al editar, vacía = no cambiarla
        if (not id_usuario or contrasena) and not (LONGITUD_MINIMA_CONTRASENA <= len(contrasena) <= 128):
            errores.append(f'La contraseña debe tener entre {LONGITUD_MINIMA_CONTRASENA} y 128 caracteres.')
        # SEGURIDAD: solo un admin puede crear administradores o modificar a un
        # admin; así un colaborador con permiso "usuarios" no puede escalar privilegios
        if not es_admin(usuario_sesion) and (rol == 'admin' or es_admin(usuario_actual)):
            errores.append('Solo un administrador puede crear o modificar administradores.')
        # SEGURIDAD: el correo es el usuario de login, no puede repetirse
        if correo:
            cur.execute("SELECT id FROM usuario WHERE LOWER(correo) = LOWER(%s) AND id <> %s", (correo, id_usuario or 0))
            if cur.fetchone():
                errores.append('Ya existe un usuario con ese correo.')

        if errores:
            mensaje = ' '.join(errores)
        elif id_usuario:  # Actualizar
            # Si es admin, asignar todos los permisos; si es colaborador, mantener los que ya tiene
            if rol == 'admin':
                permisos = ','.join(PANELES)
            else:
                # Mantener permisos existentes si es colaborador
                permisos = usuario_actual['permisos'] or ''
            cur.execute("UPDATE usuario SET documento=%s, nombres=%s, apellidos=%s, rol=%s, celular=%s, correo=%s, estado=%s, funcion=%s, permisos=%s WHERE id=%s",
                (documento, nombres, apellidos, rol, celular, correo, estado, funcion, permisos, id_usuario))
            if contrasena:
                # SEGURIDAD: la contraseña se guarda cifrada
                cur.execute("UPDATE usuario SET contrasena=%s WHERE id=%s", (generate_password_hash(contrasena), id_usuario))
            conn.commit()
            mensaje = 'Usuario actualizado.'
        else:  # Crear
            # Nuevos usuarios colaboradores sin permisos
            if rol == 'admin':
                permisos = ','.join(PANELES)
            else:
                permisos = ''  # Colaborador sin permisos inicialmente
            cur.execute("INSERT INTO usuario (documento, nombres, apellidos, rol, celular, correo, contrasena, estado, funcion, permisos) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (documento, nombres, apellidos, rol, celular, correo, generate_password_hash(contrasena), estado, funcion, permisos))
            conn.commit()
            mensaje = 'Usuario creado.'
    cur.execute(f"SELECT {COLUMNAS_USUARIO_PUBLICAS} FROM usuario ORDER BY id")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('usuarios.html', usuarios=usuarios, mensaje=mensaje)

# --- PANEL: Conceder permisos ---
@app.route('/permisos', methods=['GET', 'POST'])
def permisos():
    # Validar acceso
    acceso_negado = validar_acceso('permisos')
    if acceso_negado:
        return acceso_negado

    usuario_sesion = obtener_usuario_actual()
    conn = get_db_connection()
    cur = conn.cursor()
    mensaje = None
    if request.method == 'POST':
        id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1)
        # SEGURIDAD: se descartan paneles que no existan en la lista oficial
        paneles = [p for p in request.form.getlist('paneles') if p in PANELES]
        destino = None
        if id_usuario:
            cur.execute("SELECT id, rol FROM usuario WHERE id=%s", (id_usuario,))
            destino = cur.fetchone()
        if not destino:
            mensaje = 'Usuario inválido.'
        # SEGURIDAD: un colaborador no puede cambiar sus propios permisos ni los de un admin
        elif not es_admin(usuario_sesion) and (es_admin(destino) or destino['id'] == usuario_sesion['id']):
            mensaje = 'No puedes modificar los permisos de este usuario.'
        else:
            cur.execute("UPDATE usuario SET permisos=%s WHERE id=%s", (','.join(paneles), id_usuario))
            conn.commit()
            mensaje = 'Permisos actualizados.'
    cur.execute(f"SELECT {COLUMNAS_USUARIO_PUBLICAS} FROM usuario ORDER BY id")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('permisos.html', usuarios=usuarios, paneles=PANELES, mensaje=mensaje)

# =====================================================================
# MÓDULO: Aseo general (cronograma semanal, actividades y banco de horas)
# ---------------------------------------------------------------------
# El aseo general agrupa todas las actividades de limpieza y mantenimiento
# del establecimiento. Todo se guarda en la BD (Neon) y se puede modificar
# desde el aplicativo:
#   - Actividades: el administrador las crea, edita (descripción,
#     frecuencia, color) o desactiva. Al principio se cargan las 8 del Excel.
#   - Cronograma: cada semana (lunes a domingo) el administrador programa a
#     cada colaboradora su turno, horas, descansos y actividades del día.
#     Las horas se calculan solas a partir del turno ("6-2" = 8 horas).
#   - Percances: una actividad se puede reasignar a otra colaboradora u
#     otro día, y cualquier semana (incluso pasada) se puede volver a editar.
#   - Seguimiento: cada actividad se marca como Realizada o No realizada y
#     se pinta de color (verde, rojo, naranja si nadie la reportó).
#   - Banco de horas: la ley colombiana permite 42 horas a la semana. Las
#     horas que pasan de 42 se acumulan para devolverlas en tiempo o en
#     dinero; el administrador registra cada devolución y se ve el saldo.
#
# Resumen de lo que se agregó para este módulo:
#   - Tablas en la BD: aseo_actividad, aseo_turno, aseo_asignacion y
#     aseo_compensacion.
#   - Rutas: /aseo (tablero), /aseo/programar, /aseo/copiar,
#     /aseo/actividad, /aseo/compensar, /aseo/compensacion/<id>/eliminar,
#     /api/aseo/estado/<id> y /api/aseo/reasignar/<id>.
#
# SEGURIDAD (quién puede hacer qué):
#   - Ver el tablero: quien tenga el permiso "aseo".
#   - Programar, copiar semanas, reasignar, editar actividades y registrar
#     devoluciones de horas: SOLO administradores (sin excepciones).
#   - Marcar actividades: el administrador marca cualquiera; una
#     colaboradora solo marca las suyas.
#   - Nadie puede marcar como hecha una actividad de un día que no ha llegado.
# =====================================================================

# Frecuencias que se pueden elegir para una actividad y cada cuántos días
# debe repetirse (se usa para avisar cuando una actividad está vencida)
FRECUENCIAS_ASEO = {'Diaria': 1, 'Semanal': 7, 'Quincenal': 15, 'Mensual': 30,
                    'Cada 2 meses': 60, 'Cada 3 meses': 90, 'Semestral': 180}

# Actividades iniciales (tabla "ACTIVIDADES" del Excel): (número, frecuencia,
# color, descripción). Solo se usan la primera vez, para llenar la tabla
# aseo_actividad cuando está vacía; después se modifican desde el aplicativo.
ACTIVIDADES_ASEO_INICIALES = [
    (1, 'Semanal', '#bfbfbf', 'Aseo Diario, quemar basura, llenar tanques agua, cunetas, vías, telarañas'),
    (2, 'Semanal', '#8ea9db', 'Vidrios bodega, recepción, lavandería, habitaciones, Hipoclorito, limpiapisos'),
    (3, 'Semanal', '#f4b084', 'Aseo General (recepción, pasillo, lavandería), aseo parqueaderos'),
    (4, 'Semanal', '#92d050', 'Limpieza de lavadoras'),
    (5, 'Mensual', '#ffd966', 'Cloro tanques, Bacterias'),
    (6, 'Cada 2 meses', '#fff2cc', 'Limpieza Albercas'),
    (7, 'Cada 2 meses', '#ffff00', 'Aseo General Habitaciones'),
    (8, 'Cada 2 meses', '#00ffff', 'Aseo General de lavadoras'),
]
# SEGURIDAD: únicos estados que se aceptan al marcar una actividad
ESTADOS_ASEO = ('Pendiente', 'Realizada', 'No realizada')
DIAS_SEMANA = ('Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb', 'Dom')
# Máximo de horas semanales permitido en Colombia; lo que pase se acumula
LIMITE_HORAS_SEMANA = Decimal('42')
# Formas de devolver las horas acumuladas
TIPOS_COMPENSACION = ('Tiempo', 'Dinero')
# Lo que se escribe en "Turno" para indicar un día de descanso
TURNOS_DESCANSO = ('N', 'DESCANSO')
# SEGURIDAD: el color se inserta en el HTML, por eso solo se acepta el
# formato exacto "#rrggbb" (evita que se cuele código en la página)
REGEX_COLOR = re.compile(r'^#[0-9a-fA-F]{6}$')
# Formato de un turno: "6-2", "10p-6a", "6:30a-2:30p"...
REGEX_TURNO = re.compile(r'^\s*(\d{1,2})(?::(\d{2}))?\s*([ap])?\s*-\s*(\d{1,2})(?::(\d{2}))?\s*([ap])?\s*$', re.IGNORECASE)

# Indica si ya se revisó que existan las tablas de aseo (una vez por arranque)
_tablas_aseo_listas = False

# Crea las tablas de aseo en Neon si todavía no existen y las actualiza.
#   - aseo_actividad: catálogo de actividades (descripción, frecuencia,
#     color). "activa = FALSE" la oculta sin borrar su historial.
#   - aseo_turno: una fila por colaboradora y día con su turno, horas
#     trabajadas y si ese día es de descanso.
#   - aseo_asignacion: una fila por cada actividad asignada a una
#     colaboradora en un día, con su estado y quién la asignó/marcó.
#     UNIQUE (id_usuario, fecha, id_actividad) impide asignar dos veces la
#     misma actividad a la misma persona el mismo día.
#   - aseo_compensacion: cada devolución de horas acumuladas (en tiempo o
#     en dinero) para llevar el saldo del banco de horas.
def asegurar_tablas_aseo(conn):
    global _tablas_aseo_listas
    if _tablas_aseo_listas:
        return
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS aseo_actividad (
            id SERIAL PRIMARY KEY,
            descripcion VARCHAR(200) NOT NULL,
            frecuencia VARCHAR(20) NOT NULL,
            frecuencia_dias INTEGER NOT NULL,
            color VARCHAR(7) NOT NULL,
            activa BOOLEAN NOT NULL DEFAULT TRUE
        );
        CREATE TABLE IF NOT EXISTS aseo_turno (
            id_usuario INTEGER NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
            fecha DATE NOT NULL,
            turno VARCHAR(20) NOT NULL DEFAULT '',
            horas NUMERIC(4,1) NOT NULL DEFAULT 0,
            descanso BOOLEAN NOT NULL DEFAULT FALSE,
            actualizado_por INTEGER REFERENCES usuario(id),
            PRIMARY KEY (id_usuario, fecha)
        );
        CREATE TABLE IF NOT EXISTS aseo_asignacion (
            id SERIAL PRIMARY KEY,
            id_usuario INTEGER NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
            fecha DATE NOT NULL,
            id_actividad INTEGER NOT NULL,
            estado VARCHAR(20) NOT NULL DEFAULT 'Pendiente',
            observacion VARCHAR(200) NOT NULL DEFAULT '',
            asignado_por INTEGER REFERENCES usuario(id),
            fecha_asignacion TIMESTAMP NOT NULL DEFAULT NOW(),
            marcado_por INTEGER REFERENCES usuario(id),
            fecha_marcado TIMESTAMP,
            UNIQUE (id_usuario, fecha, id_actividad)
        );
        CREATE TABLE IF NOT EXISTS aseo_compensacion (
            id SERIAL PRIMARY KEY,
            id_usuario INTEGER NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
            fecha DATE NOT NULL,
            horas NUMERIC(5,1) NOT NULL CHECK (horas > 0),
            tipo VARCHAR(10) NOT NULL,
            nota VARCHAR(200) NOT NULL DEFAULT '',
            registrado_por INTEGER REFERENCES usuario(id),
            fecha_registro TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)
    # La primera vez se cargan las 8 actividades del Excel con su mismo número
    cur.execute("SELECT COUNT(*) AS n FROM aseo_actividad")
    if cur.fetchone()['n'] == 0:
        for numero, frecuencia, color, descripcion in ACTIVIDADES_ASEO_INICIALES:
            cur.execute("""INSERT INTO aseo_actividad (id, descripcion, frecuencia, frecuencia_dias, color)
                           VALUES (%s, %s, %s, %s, %s)""",
                        (numero, descripcion, frecuencia, FRECUENCIAS_ASEO[frecuencia], color))
        # Las actividades nuevas que cree el administrador seguirán desde el 9
        cur.execute("SELECT setval(pg_get_serial_sequence('aseo_actividad', 'id'), (SELECT MAX(id) FROM aseo_actividad))")
    # Actualización de la versión anterior del módulo: antes las actividades
    # estaban fijas en el código (números del 1 al 8). Ahora la asignación se
    # enlaza con la tabla aseo_actividad mediante una llave foránea.
    cur.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'aseo_asignacion'
                       AND column_name = 'id_actividad' AND data_type = 'smallint') THEN
                ALTER TABLE aseo_asignacion DROP CONSTRAINT IF EXISTS aseo_asignacion_id_actividad_check;
                ALTER TABLE aseo_asignacion ALTER COLUMN id_actividad TYPE INTEGER;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'aseo_asignacion_actividad_fk') THEN
                ALTER TABLE aseo_asignacion ADD CONSTRAINT aseo_asignacion_actividad_fk
                    FOREIGN KEY (id_actividad) REFERENCES aseo_actividad(id);
            END IF;
        END $$;
    """)
    conn.commit()
    cur.close()
    _tablas_aseo_listas = True

def hoy_local():
    # Fecha de hoy en Colombia (el servidor de Render trabaja en hora UTC)
    return datetime.now(LOCAL_ZONE).date()

# Devuelve el lunes de la semana que contiene la fecha recibida.
# Ejemplo: miércoles 7 de octubre -> lunes 5 de octubre.
def lunes_de(fecha):
    return fecha - timedelta(days=fecha.weekday())

# SEGURIDAD: lee la semana pedida en la URL (?semana=2026-10-05). Si viene
# vacía o mal escrita se usa la semana actual, nunca una fecha inválida.
def leer_semana(valor):
    return lunes_de(leer_fecha(valor) or hoy_local())

# Calcula las horas de un turno escrito como en el Excel:
#   sin a/p:  "6-2" = 8, "2-10" = 8, "10-6" = 8, "8-6" = 10, "12-6" = 6
#             (se asume que el turno dura menos de 12 horas)
#   con a/p:  "6a-4p" = 10, "10p-6a" = 8, "4p-6a" = 14, "6p-6a" = 12
#             (para los domingos o turnos de 12 horas o más, usa a/p)
# Devuelve None si el texto no tiene formato de turno.
def horas_de_turno(turno):
    coincidencia = REGEX_TURNO.match(turno or '')
    if not coincidencia:
        return None
    h1, m1, s1, h2, m2, s2 = coincidencia.groups()
    h1, h2, m1, m2 = int(h1), int(h2), int(m1 or 0), int(m2 or 0)
    if h1 > 24 or h2 > 24 or m1 > 59 or m2 > 59:
        return None
    if s1 and s2:
        # Con a/p se pasa a formato de 24 horas: 4p -> 16, 12a -> 0
        inicio = (h1 % 12 + (12 if s1.lower() == 'p' else 0)) * 60 + m1
        fin = (h2 % 12 + (12 if s2.lower() == 'p' else 0)) * 60 + m2
        minutos = (fin - inicio) % (24 * 60) or 24 * 60
    else:
        minutos = (h2 * 60 + m2 - h1 * 60 - m1) % (12 * 60) or 12 * 60
    return Decimal(minutos) / 60

# Clase CSS (color) de una actividad según su estado:
#   verde = realizada, rojo = no realizada, blanco = pendiente,
#   naranja = pendiente de un día que ya pasó (nadie la reportó)
def clase_estado_aseo(estado, fecha, hoy):
    if estado == 'Realizada':
        return 'realizada'
    if estado == 'No realizada':
        return 'no-realizada'
    return 'sin-reportar' if fecha < hoy else 'pendiente'

# Lee el catálogo de actividades de la BD, ordenado por número
def obtener_actividades(cur):
    cur.execute("SELECT * FROM aseo_actividad ORDER BY id")
    return cur.fetchall()

# Banco de horas de cada colaboradora, hasta la semana actual (incluida):
#   extra       = suma, semana por semana, de las horas que pasaron de 42
#   compensadas = horas ya devueltas en tiempo o en dinero
#   saldo       = extra - compensadas (lo que todavía se le debe)
# Las semanas futuras no cuentan porque esas horas aún no se han trabajado.
def calcular_banco_horas(cur):
    hasta = lunes_de(hoy_local()) + timedelta(days=6)
    cur.execute("""SELECT id_usuario, date_trunc('week', fecha)::date AS semana, SUM(horas) AS horas
                   FROM aseo_turno WHERE fecha <= %s GROUP BY id_usuario, semana""", (hasta,))
    banco = {}
    for fila in cur.fetchall():
        cuenta = banco.setdefault(fila['id_usuario'], {'extra': Decimal('0'), 'compensadas': Decimal('0')})
        cuenta['extra'] += max(Decimal('0'), fila['horas'] - LIMITE_HORAS_SEMANA)
    cur.execute("SELECT id_usuario, SUM(horas) AS horas FROM aseo_compensacion GROUP BY id_usuario")
    for fila in cur.fetchall():
        cuenta = banco.setdefault(fila['id_usuario'], {'extra': Decimal('0'), 'compensadas': Decimal('0')})
        cuenta['compensadas'] += fila['horas']
    for cuenta in banco.values():
        cuenta['saldo'] = cuenta['extra'] - cuenta['compensadas']
    return banco

# Filtro para las plantillas: {{ 8.0|horas }} muestra "8" y {{ 7.5|horas }} "7.5"
@app.template_filter('horas')
def formato_horas(valor):
    numero = Decimal(valor or 0).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP)
    return str(int(numero)) if numero == int(numero) else str(numero)

# --- PANEL: Aseo general (tablero semanal) ---
# Muestra el catálogo de actividades con su control de frecuencia, el
# cronograma de la semana por colaboradora (turnos, horas, descansos y
# actividades coloreadas) y el banco de horas.
@app.route('/aseo')
def aseo():
    # Validar acceso
    acceso_negado = validar_acceso('aseo')
    if acceso_negado:
        return acceso_negado

    usuario_sesion = obtener_usuario_actual()
    hoy = hoy_local()
    lunes = leer_semana(request.args.get('semana'))
    fechas = [lunes + timedelta(days=i) for i in range(7)]
    domingo = fechas[-1]

    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    actividades = obtener_actividades(cur)
    cur.execute("SELECT id, nombres, apellidos FROM usuario WHERE estado = 'Activo' ORDER BY nombres, apellidos")
    usuarios = cur.fetchall()

    # Turnos y actividades de la semana, agrupados por (colaboradora, fecha)
    cur.execute("SELECT * FROM aseo_turno WHERE fecha BETWEEN %s AND %s", (lunes, domingo))
    turnos = {(t['id_usuario'], t['fecha']): t for t in cur.fetchall()}
    cur.execute("""SELECT s.id, s.id_usuario, s.fecha, s.id_actividad, s.estado, s.observacion,
                          a.descripcion, a.color
                   FROM aseo_asignacion s JOIN aseo_actividad a ON a.id = s.id_actividad
                   WHERE s.fecha BETWEEN %s AND %s ORDER BY s.id_actividad""", (lunes, domingo))
    asignaciones = {}
    for a in cur.fetchall():
        a['clase'] = clase_estado_aseo(a['estado'], a['fecha'], hoy)
        asignaciones.setdefault((a['id_usuario'], a['fecha']), []).append(a)

    banco = calcular_banco_horas(cur)

    # Arma, para cada colaboradora, sus 7 días listos para la plantilla
    colaboradoras = []
    for u in usuarios:
        dias = []
        for fecha in fechas:
            turno = turnos.get((u['id'], fecha))
            dias.append({
                'fecha': fecha,
                'turno': turno['turno'] if turno else '',
                'horas': turno['horas'] if turno else Decimal('0'),
                'descanso': bool(turno and turno['descanso']),
                'actividades': asignaciones.get((u['id'], fecha), []),
            })
        todas = [a for d in dias for a in d['actividades']]
        horas_semana = sum(d['horas'] for d in dias)
        colaboradoras.append({
            'id': u['id'],
            'nombre': f"{u['nombres']} {u['apellidos']}",
            'dias': dias,
            'horas_semana': horas_semana,
            # Horas de esta semana que pasan de 42 y van al banco de horas
            'exceso': max(Decimal('0'), horas_semana - LIMITE_HORAS_SEMANA),
            'banco': banco.get(u['id'], {'extra': Decimal('0'), 'compensadas': Decimal('0'), 'saldo': Decimal('0')}),
            'total': len(todas),
            'realizadas': sum(1 for a in todas if a['estado'] == 'Realizada'),
        })

    # Control de frecuencia: para cada actividad, la última vez que se hizo
    # y si ya hay una fecha programada. Si pasó más tiempo del que indica su
    # frecuencia y no está programada, se muestra como "Vencida".
    cur.execute("""SELECT id_actividad,
                          MAX(fecha) FILTER (WHERE estado = 'Realizada') AS ultima,
                          MIN(fecha) FILTER (WHERE estado = 'Pendiente' AND fecha >= %s) AS programada
                   FROM aseo_asignacion GROUP BY id_actividad""", (hoy,))
    historial = {h['id_actividad']: h for h in cur.fetchall()}

    # Últimas devoluciones de horas registradas (para poder corregirlas)
    cur.execute("""SELECT c.id, c.fecha, c.horas, c.tipo, c.nota, u.nombres, u.apellidos
                   FROM aseo_compensacion c JOIN usuario u ON u.id = c.id_usuario
                   ORDER BY c.fecha DESC, c.id DESC LIMIT 30""")
    compensaciones = cur.fetchall()
    cur.close()
    conn.close()

    catalogo = []
    for act in actividades:
        h = historial.get(act['id'], {})
        ultima, programada = h.get('ultima'), h.get('programada')
        vence = ultima + timedelta(days=act['frecuencia_dias']) if ultima else None
        if vence and vence >= hoy:
            control = ('al-dia', f"Al día (hasta el {vence.strftime('%d/%m')})")
        elif programada:
            control = ('programada', f"Programada para el {programada.strftime('%d/%m')}")
        else:
            control = ('vencida', 'Vencida' if ultima else 'Sin registro')
        catalogo.append(dict(act, ultima=ultima, control=control))

    return render_template('aseo.html', catalogo=catalogo, colaboradoras=colaboradoras, fechas=fechas,
                           dias_semana=DIAS_SEMANA, lunes=lunes, hoy=hoy,
                           semana_anterior=lunes - timedelta(days=7), semana_siguiente=lunes + timedelta(days=7),
                           es_admin=es_admin(usuario_sesion), id_sesion=usuario_sesion['id'],
                           frecuencias=FRECUENCIAS_ASEO, limite_horas=LIMITE_HORAS_SEMANA,
                           tipos_compensacion=TIPOS_COMPENSACION, compensaciones=compensaciones)

# SEGURIDAD: las rutas que modifican el cronograma, las actividades o el
# banco de horas son solo para administradores. Devuelve la respuesta de
# error, o None si puede seguir.
def validar_admin_aseo():
    acceso_negado = validar_acceso('aseo')
    if acceso_negado:
        return acceso_negado
    if not es_admin(obtener_usuario_actual()):
        app.logger.warning('Intento de modificar aseo sin ser admin: %s', session.get('usuario'))
        flash('Solo un administrador puede modificar el cronograma de aseo.')
        return redirect(url_for('aseo'))
    return None

# --- ASEO: Guardar la semana de una colaboradora ---
# Recibe, para cada uno de los 7 días: turno, horas, si es descanso y las
# actividades marcadas. Las actividades que se quitan se borran, las nuevas
# se crean como "Pendiente" y las que ya estaban conservan su estado.
# Sirve también para corregir semanas pasadas cuando hay un percance.
@app.route('/aseo/programar', methods=['POST'])
def aseo_programar():
    acceso_negado = validar_admin_aseo()
    if acceso_negado:
        return acceso_negado
    usuario_sesion = obtener_usuario_actual()
    lunes = leer_semana(request.form.get('semana'))
    id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1)

    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    # SEGURIDAD: solo se aceptan números de actividad que existan en la BD
    ids_actividades = {a['id'] for a in obtener_actividades(cur)}

    # SEGURIDAD: se valida cada día antes de tocar la BD; si un solo dato
    # está mal no se guarda nada de la semana
    dias, errores = [], []
    for i in range(7):
        turno = leer_texto(request.form.get(f'turno_{i}'), 20, requerido=False)
        horas_texto = (request.form.get(f'horas_{i}') or '').strip()
        horas = leer_decimal(horas_texto, maximo=Decimal('24')) if horas_texto else None
        descanso = request.form.get(f'descanso_{i}') == '1' or (turno or '').upper() in TURNOS_DESCANSO
        actividades = {leer_entero(x) for x in request.form.getlist(f'act_{i}')}
        if turno is None or (horas_texto and horas is None) or not actividades <= ids_actividades:
            errores.append(DIAS_SEMANA[i])
            continue
        if horas is None:
            # Si no se digitaron las horas, se calculan a partir del turno
            horas = horas_de_turno(turno) or Decimal('0')
        if descanso:
            # Un día de descanso no lleva horas ni actividades
            horas, actividades = Decimal('0'), set()
            turno = turno or 'N'
        dias.append((lunes + timedelta(days=i), turno, horas, descanso, actividades))

    destino = None
    if id_usuario:
        cur.execute("SELECT id FROM usuario WHERE id=%s", (id_usuario,))
        destino = cur.fetchone()
    if not destino:
        flash('Colaboradora inválida.')
    elif errores:
        flash('Revisa los datos de: ' + ', '.join(errores) + '. El turno admite hasta 20 caracteres y las horas van de 0 a 24.')
    else:
        for fecha, turno, horas, descanso, actividades in dias:
            if not turno and not horas and not descanso:
                # Día vacío: se borra el turno para no guardar filas sin datos
                cur.execute("DELETE FROM aseo_turno WHERE id_usuario=%s AND fecha=%s", (id_usuario, fecha))
            else:
                cur.execute("""INSERT INTO aseo_turno (id_usuario, fecha, turno, horas, descanso, actualizado_por)
                               VALUES (%s, %s, %s, %s, %s, %s)
                               ON CONFLICT (id_usuario, fecha) DO UPDATE SET turno=EXCLUDED.turno, horas=EXCLUDED.horas,
                                   descanso=EXCLUDED.descanso, actualizado_por=EXCLUDED.actualizado_por""",
                            (id_usuario, fecha, turno, horas, descanso, usuario_sesion['id']))
            # Se borran las actividades que se desmarcaron ese día...
            cur.execute("DELETE FROM aseo_asignacion WHERE id_usuario=%s AND fecha=%s AND NOT (id_actividad = ANY(%s))",
                        (id_usuario, fecha, list(actividades)))
            # ...y se agregan las nuevas; "DO NOTHING" deja intactas (con su
            # estado) las que ya estaban asignadas
            for id_actividad in sorted(actividades):
                cur.execute("""INSERT INTO aseo_asignacion (id_usuario, fecha, id_actividad, asignado_por)
                               VALUES (%s, %s, %s, %s) ON CONFLICT (id_usuario, fecha, id_actividad) DO NOTHING""",
                            (id_usuario, fecha, id_actividad, usuario_sesion['id']))
        conn.commit()
        app.logger.info('Semana de aseo %s del usuario %s programada por %s', lunes, id_usuario, usuario_sesion['correo'])
        total = sum(d[2] for d in dias)
        if total > LIMITE_HORAS_SEMANA:
            flash(f'Semana programada. Atención: suma {formato_horas(total)} horas, '
                  f'{formato_horas(total - LIMITE_HORAS_SEMANA)} por encima del límite de {LIMITE_HORAS_SEMANA} '
                  f'(se acumulan en el banco de horas).')
        else:
            flash('Semana programada.')
    cur.close()
    conn.close()
    return redirect(url_for('aseo', semana=lunes.isoformat()))

# --- ASEO: Copiar la semana anterior ---
# Copia los turnos y actividades de la semana pasada (de todas las
# colaboradoras) a la semana que se está viendo. Las actividades copiadas
# quedan como "Pendiente". Lo que ya estaba programado no se sobrescribe.
@app.route('/aseo/copiar', methods=['POST'])
def aseo_copiar():
    acceso_negado = validar_admin_aseo()
    if acceso_negado:
        return acceso_negado
    usuario_sesion = obtener_usuario_actual()
    lunes = leer_semana(request.form.get('semana'))
    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    # "fecha + 7" mueve cada registro exactamente una semana adelante.
    # Las actividades desactivadas no se copian.
    cur.execute("""INSERT INTO aseo_turno (id_usuario, fecha, turno, horas, descanso, actualizado_por)
                   SELECT id_usuario, fecha + 7, turno, horas, descanso, %s FROM aseo_turno
                   WHERE fecha BETWEEN %s AND %s ON CONFLICT (id_usuario, fecha) DO NOTHING""",
                (usuario_sesion['id'], lunes - timedelta(days=7), lunes - timedelta(days=1)))
    cur.execute("""INSERT INTO aseo_asignacion (id_usuario, fecha, id_actividad, asignado_por)
                   SELECT s.id_usuario, s.fecha + 7, s.id_actividad, %s
                   FROM aseo_asignacion s JOIN aseo_actividad a ON a.id = s.id_actividad AND a.activa
                   WHERE s.fecha BETWEEN %s AND %s ON CONFLICT (id_usuario, fecha, id_actividad) DO NOTHING""",
                (usuario_sesion['id'], lunes - timedelta(days=7), lunes - timedelta(days=1)))
    copiadas = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    app.logger.info('Semana de aseo %s copiada de la anterior por %s', lunes, usuario_sesion['correo'])
    flash(f'Semana anterior copiada ({copiadas} actividades nuevas).' if copiadas else 'No había actividades nuevas para copiar de la semana anterior.')
    return redirect(url_for('aseo', semana=lunes.isoformat()))

# --- ASEO: Crear o editar una actividad del catálogo ---
# Si el formulario trae "id_actividad" se edita esa actividad; si no, se
# crea una nueva. Las actividades no se borran: se desactivan, para no
# perder el historial de cuándo se hicieron.
@app.route('/aseo/actividad', methods=['POST'])
def aseo_actividad():
    acceso_negado = validar_admin_aseo()
    if acceso_negado:
        return acceso_negado
    usuario_sesion = obtener_usuario_actual()
    id_actividad = leer_entero(request.form.get('id_actividad'), minimo=1) if request.form.get('id_actividad') else None
    descripcion = leer_texto(request.form.get('descripcion'), 200)
    frecuencia = request.form.get('frecuencia')
    color = (request.form.get('color') or '').strip()
    activa = request.form.get('activa') == '1'
    semana = leer_semana(request.form.get('semana'))

    # SEGURIDAD: descripción obligatoria, frecuencia de la lista y color "#rrggbb"
    if descripcion is None or frecuencia not in FRECUENCIAS_ASEO or not REGEX_COLOR.match(color):
        flash('Revisa la actividad: la descripción es obligatoria (máx. 200 caracteres) y la frecuencia y el color deben ser válidos.')
        return redirect(url_for('aseo', semana=semana.isoformat()))

    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    if id_actividad:
        cur.execute("""UPDATE aseo_actividad SET descripcion=%s, frecuencia=%s, frecuencia_dias=%s, color=%s, activa=%s
                       WHERE id=%s""", (descripcion, frecuencia, FRECUENCIAS_ASEO[frecuencia], color, activa, id_actividad))
        mensaje = 'Actividad actualizada.' if cur.rowcount else 'La actividad no existe.'
    else:
        cur.execute("""INSERT INTO aseo_actividad (descripcion, frecuencia, frecuencia_dias, color)
                       VALUES (%s, %s, %s, %s) RETURNING id""", (descripcion, frecuencia, FRECUENCIAS_ASEO[frecuencia], color))
        mensaje = f"Actividad {cur.fetchone()['id']} creada."
    conn.commit()
    cur.close()
    conn.close()
    app.logger.info('Actividad de aseo %s guardada por %s', id_actividad or 'nueva', usuario_sesion['correo'])
    flash(mensaje)
    return redirect(url_for('aseo', semana=semana.isoformat()))

# --- ASEO: Registrar una devolución de horas del banco ---
# Cuando a una colaboradora se le devuelven horas acumuladas (con tiempo
# libre o pagándolas), se registra aquí y se descuentan de su saldo.
@app.route('/aseo/compensar', methods=['POST'])
def aseo_compensar():
    acceso_negado = validar_admin_aseo()
    if acceso_negado:
        return acceso_negado
    usuario_sesion = obtener_usuario_actual()
    semana = leer_semana(request.form.get('semana'))
    id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1)
    fecha = leer_fecha(request.form.get('fecha'))
    horas = leer_decimal(request.form.get('horas'), minimo=Decimal('0.5'), maximo=Decimal('500'))
    tipo = request.form.get('tipo')
    nota = leer_texto(request.form.get('nota'), 200, requerido=False)

    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    saldo = calcular_banco_horas(cur).get(id_usuario, {}).get('saldo', Decimal('0'))
    # SEGURIDAD: datos válidos y nunca devolver más horas de las acumuladas
    if not id_usuario or not fecha or horas is None or tipo not in TIPOS_COMPENSACION or nota is None:
        flash('Revisa la devolución: colaboradora, fecha, horas (mínimo 0.5) y tipo son obligatorios.')
    elif horas > saldo:
        flash(f'No se pueden devolver {formato_horas(horas)} horas: el saldo de esta colaboradora es {formato_horas(saldo)} horas.')
    else:
        cur.execute("""INSERT INTO aseo_compensacion (id_usuario, fecha, horas, tipo, nota, registrado_por)
                       VALUES (%s, %s, %s, %s, %s, %s)""", (id_usuario, fecha, horas, tipo, nota, usuario_sesion['id']))
        conn.commit()
        app.logger.info('Devolución de %s horas (%s) al usuario %s registrada por %s', horas, tipo, id_usuario, usuario_sesion['correo'])
        flash('Devolución de horas registrada.')
    cur.close()
    conn.close()
    return redirect(url_for('aseo', semana=semana.isoformat()))

# --- ASEO: Eliminar una devolución de horas (para corregir errores) ---
@app.route('/aseo/compensacion/<int:id_compensacion>/eliminar', methods=['POST'])
def aseo_compensacion_eliminar(id_compensacion):
    acceso_negado = validar_admin_aseo()
    if acceso_negado:
        return acceso_negado
    usuario_sesion = obtener_usuario_actual()
    semana = leer_semana(request.form.get('semana'))
    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    cur.execute("DELETE FROM aseo_compensacion WHERE id=%s", (id_compensacion,))
    conn.commit()
    flash('Devolución eliminada.' if cur.rowcount else 'La devolución no existe.')
    cur.close()
    conn.close()
    app.logger.info('Devolución de horas %s eliminada por %s', id_compensacion, usuario_sesion['correo'])
    return redirect(url_for('aseo', semana=semana.isoformat()))

# --- ASEO: Marcar una actividad (API usada por el tablero con fetch) ---
# Recibe {"estado": "Realizada" | "No realizada" | "Pendiente", "observacion": "..."}
# y devuelve el nuevo color para pintar la actividad sin recargar la página.
@app.route('/api/aseo/estado/<int:id_asignacion>', methods=['POST'])
def api_aseo_estado(id_asignacion):
    # SEGURIDAD: igual que en las demás APIs, se exige sesión y permiso
    if not tiene_permiso('aseo'):
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    usuario_sesion = obtener_usuario_actual()
    data = request.get_json(silent=True) or {}
    estado = data.get('estado')
    observacion = leer_texto(data.get('observacion'), 200, requerido=False)
    # SEGURIDAD: solo estados conocidos y observaciones de largo razonable
    if estado not in ESTADOS_ASEO or observacion is None:
        return jsonify({'ok': False, 'msg': 'Estado u observación inválidos'}), 400

    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    cur.execute("SELECT id, id_usuario, fecha FROM aseo_asignacion WHERE id=%s", (id_asignacion,))
    asignacion = cur.fetchone()
    hoy = hoy_local()
    error = None
    if not asignacion:
        error = ('La actividad no existe.', 404)
    # SEGURIDAD: una colaboradora solo puede marcar sus propias actividades
    elif not es_admin(usuario_sesion) and asignacion['id_usuario'] != usuario_sesion['id']:
        error = ('Solo puedes marcar tus propias actividades.', 403)
    # No se puede reportar como hecha (o no hecha) una actividad de un día futuro
    elif estado != 'Pendiente' and asignacion['fecha'] > hoy:
        error = ('No puedes marcar una actividad de un día que todavía no llega.', 400)
    if error:
        cur.close()
        conn.close()
        return jsonify({'ok': False, 'msg': error[0]}), error[1]

    # Al volver a "Pendiente" se borra quién la marcó y cuándo
    marcada = estado != 'Pendiente'
    cur.execute("""UPDATE aseo_asignacion SET estado=%s, observacion=%s, marcado_por=%s,
                   fecha_marcado=CASE WHEN %s THEN NOW() ELSE NULL END WHERE id=%s""",
                (estado, observacion, usuario_sesion['id'] if marcada else None, marcada, id_asignacion))
    conn.commit()
    cur.close()
    conn.close()
    app.logger.info('Actividad de aseo %s marcada "%s" por %s', id_asignacion, estado, usuario_sesion['correo'])
    return jsonify({'ok': True, 'estado': estado, 'observacion': observacion,
                    'clase': clase_estado_aseo(estado, asignacion['fecha'], hoy)})

# --- ASEO: Reasignar una actividad por un percance (solo admin) ---
# Recibe {"id_usuario": 5, "fecha": "2026-10-07"} y pasa la actividad a otra
# colaboradora y/o a otro día. Vuelve a quedar "Pendiente".
@app.route('/api/aseo/reasignar/<int:id_asignacion>', methods=['POST'])
def api_aseo_reasignar(id_asignacion):
    usuario_sesion = obtener_usuario_actual()
    # SEGURIDAD: solo administradores pueden mover actividades
    if not tiene_permiso('aseo') or not es_admin(usuario_sesion):
        return jsonify({'ok': False, 'msg': 'Solo un administrador puede reasignar actividades.'}), 403
    data = request.get_json(silent=True) or {}
    id_usuario = leer_entero(data.get('id_usuario'), minimo=1)
    fecha = leer_fecha(data.get('fecha'))
    if not id_usuario or not fecha:
        return jsonify({'ok': False, 'msg': 'Colaboradora o fecha inválida.'}), 400

    conn = get_db_connection()
    asegurar_tablas_aseo(conn)
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuario WHERE id=%s AND estado='Activo'", (id_usuario,))
    destino_valido = cur.fetchone()
    cur.execute("SELECT id_actividad FROM aseo_asignacion WHERE id=%s", (id_asignacion,))
    asignacion = cur.fetchone()
    respuesta = None
    if not destino_valido or not asignacion:
        respuesta = ({'ok': False, 'msg': 'La actividad o la colaboradora no existen.'}, 404)
    else:
        # No se puede mover a quien ya tiene esa misma actividad ese día
        cur.execute("SELECT 1 FROM aseo_asignacion WHERE id_usuario=%s AND fecha=%s AND id_actividad=%s AND id<>%s",
                    (id_usuario, fecha, asignacion['id_actividad'], id_asignacion))
        if cur.fetchone():
            respuesta = ({'ok': False, 'msg': 'Esa colaboradora ya tiene esta actividad ese día.'}, 409)
        else:
            cur.execute("""UPDATE aseo_asignacion SET id_usuario=%s, fecha=%s, estado='Pendiente', observacion='',
                           marcado_por=NULL, fecha_marcado=NULL, asignado_por=%s WHERE id=%s""",
                        (id_usuario, fecha, usuario_sesion['id'], id_asignacion))
            conn.commit()
            app.logger.info('Actividad de aseo %s reasignada al usuario %s (%s) por %s',
                            id_asignacion, id_usuario, fecha, usuario_sesion['correo'])
            respuesta = ({'ok': True}, 200)
    cur.close()
    conn.close()
    return jsonify(respuesta[0]), respuesta[1]

if __name__ == '__main__':
    app.run(debug=MODO_DEBUG)
