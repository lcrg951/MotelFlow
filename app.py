# API para cambiar estado y tiempo de habitación
from flask import jsonify
# --- RUTAS DE TURNOS (deben ir después de la definición de app) ---
from flask import jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, redirect, url_for, request, session, flash



app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Cambia esto por una clave segura en producción

# Configuración de conexión a NeonDB PostgreSQL
DB_CONFIG = {
    'dbname': 'neondb',
    'user': 'neondb_owner',
    'password': 'npg_EZt5bfOFHhN9',
    'host': 'ep-holy-shadow-am69l4k1-pooler.c-5.us-east-1.aws.neon.tech',
    'port': 5432,
    'sslmode': 'require'
}

def get_db_connection():
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    return conn

# Función para obtener usuario por correo
def obtener_usuario_por_correo(correo):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM usuario WHERE correo = %s", (correo,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    return usuario

# Función para obtener los permisos del usuario actual
def obtener_permisos_usuario():
    if 'usuario' not in session:
        return []
    usuario = obtener_usuario_por_correo(session['usuario'])
    if not usuario:
        return []
    if usuario['rol'].lower() == 'admin':
        return ['habitaciones', 'turnos', 'inventario', 'ventas', 'nomina', 'usuarios', 'permisos', 'aseo']
    else:
        # Colaborador: obtener permisos asignados
        if usuario.get('permisos'):
            return [p.strip() for p in usuario['permisos'].split(',') if p.strip()]
        return []

# Función para validar si el usuario tiene permiso para un panel
def tiene_permiso(panel_requerido):
    permisos = obtener_permisos_usuario()
    return panel_requerido in permisos

# Función para redirigir si no tiene permiso
def validar_acceso(panel_requerido):
    if not tiene_permiso(panel_requerido):
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
    room_id = int(request.form.get('room_id'))
    deco_ids = request.form.getlist('decoraciones')
    tiempo_id = request.form.get('tiempo')
    room = next((r for r in ROOMS if r['id'] == room_id), None)
    decoraciones = [d for d in DECORACIONES if str(d['id']) in deco_ids]
    tiempo = next((t for t in TIEMPOS if t['id'] == tiempo_id), None)
    if room:
        reservas = session.get('reservas', [])
        reservas.append({'habitacion': room, 'decoraciones': decoraciones, 'tiempo': tiempo})
        session['reservas'] = reservas
    return redirect(url_for('cart'))



# Ruta de login con autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form.get('usuario')
        contrasena = request.form.get('contrasena')
        usuario = obtener_usuario_por_correo(correo)
        if usuario and usuario['contrasena'] == contrasena:
            session['usuario'] = usuario['correo']
            session['rol'] = usuario['rol']
            # Ambos Admin y Colaborador van a /admin que redirige a /panel_admin
            return redirect(url_for('admin'))
        else:
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
    if 'usuario' not in session:
        return redirect(url_for('login'))
    usuario = obtener_usuario_por_correo(session['usuario'])
    if not usuario or usuario['rol'].lower() != 'colaborador':
        flash('Acceso restringido.')
        return redirect(url_for('login'))

    turno_abierto = False
    fecha_apertura = None
    # Si ya existe un turno abierto en sesión, verificar en la BD.
    if 'turno_id' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM turno WHERE id = %s AND estado IN ('Abierto', 'abierto')", (session['turno_id'],))
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
        numero = request.form['numero']
        tipo = request.form['tipo']
        precio = request.form['precio_estandar']
        cur.execute("INSERT INTO habitacion (numero, tipo, precio_estandar) VALUES (%s, %s, %s)", (numero, tipo, precio))
        conn.commit()
    cur.execute("SELECT * FROM habitacion ORDER BY id")
    habitaciones = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('habitaciones.html', habitaciones=habitaciones)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    return render_template('admin.html')

# Crear turno (POST desde empleados.html)
@app.route('/abrir_turno', methods=['POST'])
def abrir_turno():
    if 'usuario' not in session:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    correo = session['usuario']
    usuario = obtener_usuario_por_correo(correo)
    if not usuario:
        return jsonify({'ok': False, 'msg': 'Usuario no encontrado'}), 404
    base_caja = request.json.get('base_caja')
    if base_caja is None or str(base_caja).strip() == '':
        return jsonify({'ok': False, 'msg': 'Monto requerido'}), 400
    # Insertar turno
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO turno (id_usuario, base_caja, estado)
        VALUES (%s, %s, 'Abierto')
        RETURNING id, fecha_apertura
    """, (usuario['id'], base_caja))
    turno = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    session['turno_id'] = turno['id']
    return jsonify({'ok': True, 'turno_id': turno['id'], 'fecha_apertura': turno['fecha_apertura']})

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
    session.pop('turno_id', None)
    session.pop('usuario', None)
    session.pop('rol', None)
    return jsonify({'ok': True})

# Logout para Admin (sin registrar turno)
@app.route('/logout', methods=['GET'])
def logout():
    session.pop('turno_id', None)
    session.pop('usuario', None)
    session.pop('rol', None)
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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE turno SET fecha_cierre = CURRENT_TIMESTAMP, estado = 'Cerrado', observaciones = %s
        WHERE id = %s
    """, (observaciones, turno_id))
    conn.commit()
    cur.close()
    conn.close()
    session.pop('turno_id', None)
    session.pop('usuario', None)
    session.pop('rol', None)
    return jsonify({'ok': True})

# --- RUTAS DE TURNOS (deben ir después de la definición de app) ---
# (Mover esto después de la definición de app)

# Panel de administración principal
@app.route('/panel_admin')
def panel_admin():
    permisos = obtener_permisos_usuario()
    es_admin = False
    es_colaborador = False
    
    if 'usuario' in session:
        usuario = obtener_usuario_por_correo(session['usuario'])
        if usuario:
            es_admin = usuario['rol'].lower() == 'admin'
            es_colaborador = usuario['rol'].lower() == 'colaborador'
            
            # Si es Admin, mostrar vista admin_panel.html sin turnos
            if es_admin:
                return render_template('admin_panel.html', permisos=permisos)
            
            # Si es Colaborador, verificar turno abierto
            if es_colaborador:
                turno_abierto = False
                fecha_apertura = None
                
                # Verificar si tiene turno abierto
                if 'turno_id' in session:
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("SELECT * FROM turno WHERE id = %s AND estado IN ('Abierto', 'abierto')", (session['turno_id'],))
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
        nombre = request.form['nombre']
        stock_actual = request.form['stock_actual']
        precio_costo = request.form['precio_costo']
        precio_venta = request.form['precio_venta']
        stock_minimo = request.form['stock_minimo']
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
from flask import jsonify

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
        id_habitacion = request.form['id_habitacion']
        id_producto = request.form.get('id_producto')
        cantidad = request.form.get('cantidad')
        accion = request.form.get('accion')
        if accion == 'agregar_producto' and id_producto and cantidad:
            # Agregar producto al carrito
            if id_habitacion not in carrito:
                carrito[id_habitacion] = []
            carrito[id_habitacion].append({'id_producto': id_producto, 'cantidad': int(cantidad)})
            session['carrito'] = carrito
            mensaje = 'Producto agregado al carrito.'
        elif accion == 'registrar_venta' and usuario_id:
            # Registrar venta solo al ocupar
            productos_hab = carrito.get(id_habitacion, [])
            total = 0
            for item in productos_hab:
                cur.execute("SELECT precio_venta, stock_actual FROM inventario WHERE id = %s", (item['id_producto'],))
                prod = cur.fetchone()
                if not prod or prod['stock_actual'] < item['cantidad']:
                    mensaje = 'Stock insuficiente para algún producto.'
                    break
                total += float(prod['precio_venta']) * item['cantidad']
            # Sumar valor de la habitación
            cur.execute("SELECT precio_estandar FROM habitacion WHERE id = %s", (id_habitacion,))
            hab = cur.fetchone()
            if hab:
                total += float(hab['precio_estandar'])
            if not mensaje:
                for item in productos_hab:
                    cur.execute("SELECT precio_venta FROM inventario WHERE id = %s", (item['id_producto'],))
                    prod = cur.fetchone()
                    total_pago = float(prod['precio_venta']) * item['cantidad']
                    cur.execute("INSERT INTO venta (id_usuario, id_habitacion, id_producto, cantidad, total_pago) VALUES (%s, %s, %s, %s, %s)",
                        (usuario_id, id_habitacion, item['id_producto'], item['cantidad'], total_pago))
                    cur.execute("UPDATE inventario SET stock_actual = stock_actual - %s WHERE id = %s", (item['cantidad'], item['id_producto']))
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

@app.route('/nomina')
def nomina():
    # Validar acceso
    acceso_negado = validar_acceso('nomina')
    if acceso_negado:
        return acceso_negado
    
    return render_template('nomina.html')

@app.route('/api/habitacion_estado/<int:hab_id>', methods=['POST'])
def api_habitacion_estado(hab_id):
    data = request.get_json()
    estado = data.get('estado')
    tiempo = data.get('tiempo')
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


# --- PANEL: Crear usuario ---
@app.route('/usuarios', methods=['GET', 'POST'])
def usuarios():
    # Validar acceso
    acceso_negado = validar_acceso('usuarios')
    if acceso_negado:
        return acceso_negado
    
    conn = get_db_connection()
    cur = conn.cursor()
    mensaje = None
    if request.method == 'POST':
        id_usuario = request.form.get('id_usuario')
        documento = request.form.get('documento')
        nombres = request.form.get('nombres')
        apellidos = request.form.get('apellidos')
        rol = request.form.get('rol')
        celular = request.form.get('celular')
        correo = request.form.get('correo')
        contrasena = request.form.get('contrasena')
        estado = request.form.get('estado') or 'Activo'
        funcion = request.form.get('funcion')
        
        if id_usuario:  # Actualizar
            # Obtener permisos actuales para no sobrescribir si es colaborador
            cur.execute("SELECT permisos, rol FROM usuario WHERE id=%s", (id_usuario,))
            usuario_actual = cur.fetchone()
            # Si es admin, asignar todos los permisos; si es colaborador, mantener los que ya tiene
            if rol == 'admin':
                permisos = 'habitaciones,turnos,inventario,ventas,nomina,usuarios,permisos,aseo'
            else:
                # Mantener permisos existentes si es colaborador
                permisos = usuario_actual['permisos'] if usuario_actual else ''
            cur.execute("UPDATE usuario SET documento=%s, nombres=%s, apellidos=%s, rol=%s, celular=%s, correo=%s, contrasena=%s, estado=%s, funcion=%s, permisos=%s WHERE id=%s",
                (documento, nombres, apellidos, rol, celular, correo, contrasena, estado, funcion, permisos, id_usuario))
            mensaje = 'Usuario actualizado.'
        else:  # Crear
            # Nuevos usuarios colaboradores sin permisos
            if rol == 'admin':
                permisos = 'habitaciones,turnos,inventario,ventas,nomina,usuarios,permisos,aseo'
            else:
                permisos = ''  # Colaborador sin permisos inicialmente
            cur.execute("INSERT INTO usuario (documento, nombres, apellidos, rol, celular, correo, contrasena, estado, funcion, permisos) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (documento, nombres, apellidos, rol, celular, correo, contrasena, estado, funcion, permisos))
            mensaje = 'Usuario creado.'
        conn.commit()
    cur.execute("SELECT * FROM usuario ORDER BY id")
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
    
    conn = get_db_connection()
    cur = conn.cursor()
    mensaje = None
    if request.method == 'POST':
        id_usuario = request.form.get('id_usuario')
        paneles = request.form.getlist('paneles')
        cur.execute("UPDATE usuario SET permisos=%s WHERE id=%s", (','.join(paneles), id_usuario))
        conn.commit()
        mensaje = 'Permisos actualizados.'
    cur.execute("SELECT * FROM usuario ORDER BY id")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    paneles = ['habitaciones', 'turnos', 'inventario', 'ventas', 'nomina', 'usuarios', 'permisos', 'aseo']
    return render_template('permisos.html', usuarios=usuarios, paneles=paneles, mensaje=mensaje)

# --- PANEL: Aseo general (vacío) ---
@app.route('/aseo')
def aseo():
    # Validar acceso
    acceso_negado = validar_acceso('aseo')
    if acceso_negado:
        return acceso_negado
    
    return render_template('aseo.html')

if __name__ == '__main__':
    app.run(debug=True)
