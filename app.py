
from flask import Flask, render_template, redirect, url_for, request, session


app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Cambia esto por una clave segura en producción

DECORACIONES = [
    {
        'id': 1,
        'nombre': 'Decoración Romántica',
        'descripcion': 'Pétalos de rosa, velas aromáticas y luz tenue.',
        'precio': 600
    },
    {
        'id': 2,
        'nombre': 'Cumpleaños Especial',
        'descripcion': 'Globos, pastel pequeño y banner personalizado.',
        'precio': 800
    },
    {
        'id': 3,
        'nombre': 'Decoración Spa',
        'descripcion': 'Aromaterapia, batas y decoración relajante.',
        'precio': 700
    },
    {
        'id': 4,
        'nombre': 'Aniversario',
        'descripcion': 'Champagne, flores y decoración elegante.',
        'precio': 1000
    }
]

# Catálogo de habitaciones
ROOMS = [
    {
        'id': 1,
        'nombre': 'Suite Presidencial',
        'descripcion': 'Habitación de lujo con jacuzzi, cama king size, minibar y decoración exclusiva.',
        'precio': 2500
    },
    {
        'id': 2,
        'nombre': 'Suite Romántica',
        'descripcion': 'Ambiente íntimo, iluminación especial, cama queen size y baño privado.',
        'precio': 1800
    },
    {
        'id': 3,
        'nombre': 'Habitación Estándar',
        'descripcion': 'Comodidad y privacidad, cama matrimonial, TV y aire acondicionado.',
        'precio': 1200
    },
    {
        'id': 4,
        'nombre': 'Habitación Ejecutiva',
        'descripcion': 'Espacio moderno, escritorio, WiFi y servicios premium para negocios.',
        'precio': 1600
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')

# Ruta para eliminar una reserva por índice
@app.route('/eliminar/<int:idx>', methods=['POST'])
def eliminar(idx):
    reservas = session.get('reservas', [])
    if 0 <= idx < len(reservas):
        reservas.pop(idx)
        session['reservas'] = reservas
    return redirect(url_for('cart'))

@app.route('/empleados', methods=['POST'])
def empleados():
    return render_template('empleados.html')

@app.route('/admin', methods=['POST'])
def admin():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
