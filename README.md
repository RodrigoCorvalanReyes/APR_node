}# Simulador Modbus TCP PM2120 - Estacion Virtual

Una aplicación web Node.js que simula un medidor de energía PM2120 con datos Modbus TCP en tiempo real.

## Características

- ✅ **72 Registros PM2120**: Simula registros clave del medidor de energía PM2120 (direcciones 3000 en adelante).
- ✅ **Control de Bombas**: 2 switches para simular bombas de agua (ON/OFF) en los registros 4000-4001.
- ✅ **Nivel de Tanque**: Control deslizable para simular el nivel de agua en el registro 4002.
- ✅ **Interfaz Web**: Panel de control industrial con visualización y control en tiempo real.
- ✅ **Configuración Flexible**: IP, puerto, ID de dispositivo e intervalo de actualización configurables.
- ✅ **Formato Estándar**: Compatible con ModScan32 y otros clientes Modbus usando formato de punto flotante estándar (Big-Endian).
- ✅ **Logging Detallado**: Registro completo de transacciones Modbus en la consola para depuración.

## Requisitos

- Node.js 14.0 o superior
- npm (incluido con Node.js)

## Instalación

1.  **Clonar o descargar** el proyecto.
2.  **Instalar dependencias** desde la terminal:
    ```bash
    npm install
    ```

## Uso

### 1. Iniciar el Servidor (Modo Desarrollo)
En la terminal, ejecuta:
```bash
npm start
```
Esto iniciará el servidor en primer plano. Es útil para desarrollo y depuración.

### 2. Iniciar como Servicio (Modo Producción con PM2)
Para ejecutar la aplicación como un servicio persistente en segundo plano, se recomienda usar `pm2`.

1.  **Instalar PM2 globalmente**:
    ```bash
    npm install pm2 -g
    ```
2.  **Iniciar la aplicación con PM2**:
    ```bash
    pm2 start app.js --name "virtual-rdw"
    ```
3.  **Guardar la configuración para reinicios**:
    ```bash
    pm2 save
    ```
4.  **Generar script de inicio automático**:
    ```bash
    pm2 startup
    ```
    (Sigue las instrucciones que aparecen en la terminal para completar este paso).

#### Comandos útiles de PM2
- `pm2 list`: Muestra el estado de todas las aplicaciones.
- `pm2 stop virtual-rdw`: Detiene la aplicación.
- `pm2 restart virtual-rdw`: Reinicia la aplicación.
- `pm2 logs virtual-rdw`: Muestra los registros en tiempo real.
- `pm2 delete virtual-rdw`: Elimina la aplicación de la lista de PM2.


### 3. Configurar la Aplicación
Abre tu navegador en: `http://localhost:3001`

Configura los parámetros según tu necesidad:

- **IP Modbus**: `0.0.0.0` para escuchar en todas las interfaces de red o `127.0.0.1` para uso local.
- **Puerto Modbus**: `502` (puerto estándar).
- **Device ID**: `1` (identificador del esclavo Modbus).
- **Intervalo**: Tiempo en segundos para la generación de nuevos datos simulados.

### 4. Usar con un Cliente Modbus (Ej. Modscan)
Configuración Recomendada:
- **Connection**: Modbus TCP/IP
- **IP Address**: `127.0.0.1` (si el simulador corre en la misma máquina).
- **Port**: `502`
- **Modbus Point Type**: Holding Registers (4X).
- **Address**: `3000` (para registros PM2120) o `4000` (para bombas/tanque).
- **Length**: La cantidad de registros que deseas leer (ej. 50).
- **Slave ID**: `1` (o el que hayas configurado).
- **Display Format**: Float (No es necesario usar la opción "Swapped" o "Little-Endian").

## Mapa de Registros

### Registros PM2120 (Comienzan en 3000)
Los registros siguen el mapa oficial del PM2120 con datos simulados realistas.

| Registro    | Descripción   | Tipo    | Rango Simulado  |
|-------------|---------------|---------|-----------------|
| 3000-3001   | Current A     | FLOAT32 | 10.0-30.0 A     |
| 3002-3003   | Current B     | FLOAT32 | 10.0-30.0 A     |
| 3004-3005   | Current C     | FLOAT32 | 10.0-30.0 A     |
| 3020-3021   | Voltage A-B   | FLOAT32 | 220.0-240.0 V   |
| ...         | ...           | ...     | ...             |

### Registros de Control (4000-4002)

| Registro | Descripción  | Tipo   | Valores          |
|----------|--------------|--------|------------------|
| 4000     | Bomba 1      | UINT16 | 0 (OFF) / 1 (ON) |
| 4001     | Bomba 2      | UINT16 | 0 (OFF) / 1 (ON) |
| 4002     | Nivel Tanque | UINT16 | 0 a 100 (%)      |

## Estructura del Proyecto
```
├── app.js                      # Servidor principal (Express + Modbus TCP)
├── package.json               # Dependencias y scripts del proyecto
├── register_table_PM2120.json # Tabla de configuración de registros
├── public/
│   └── index.html             # Interfaz web del panel de control
└── README.md                  # Este archivo
```

## Solución de Problemas

### Error "Modbus Exception Response"
- **Verificar Dirección Inicial**: Asegúrate de que estás consultando desde la dirección `3000` o `4000`. Recuerda que algunos clientes usan base 0, por lo que podrías necesitar consultar `2999`. El simulador está diseñado para funcionar con clientes base 1 como Modscan.
- **Revisar Firewall**: Confirma que el puerto `502` no esté bloqueado.
- **Verificar Logs**: La consola de Node.js (o los logs de `pm2`) muestra detalles de cada transacción y te dará pistas sobre el error.

### Lecturas Incorrectas
- **Formato Incorrecto**: Asegúrate de que tu cliente Modbus esté configurado para leer Punto Flotante (Float) en formato Big-Endian (estándar, no swapped).
- **Device ID no coincide**: El ID en tu cliente debe ser el mismo que el configurado en la interfaz web (por defecto es 1).
