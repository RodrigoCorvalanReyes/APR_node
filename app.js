const express = require('express');
const bodyParser = require('body-parser');
const ModbusRTU = require('modbus-serial');
const path = require('path'); // <<< CORREGIDO EL ERROR DE INICIALIZACIÓN
const net = require('net');
const fs = require('fs');
const mqtt = require('mqtt');

// --- Configuración MQTT (Thingsboard) ---
const TB_HOST = "";
const TB_PORT = ;
const TB_TOKEN = ""; // Access Token del dispositivo
const TB_TOPIC = "";
const MQTT_CLIENT_ID = `modbus-gateway-${Math.random().toString(16).substr(2, 8)}`;

// --- Cliente MQTT ---
let mqttClient = null;

const app = express();
const PORT = 3001;

// Cargar configuración de registros PM2120
let pm2120Registers = [];
try {
    pm2120Registers = JSON.parse(fs.readFileSync('./register_table_PM2120.json', 'utf8'));
    console.log(`[INIT] Cargados ${pm2120Registers.length} registros del PM2120`);
} catch (error) {
    console.error('[INIT] Error cargando registros PM2120:', error.message);
    process.exit(1);
}

// Configuración por defecto
let config = {
    deviceId: 1,
    interval: 60000, // 60 segundos en milisegundos
    modbusPort: 502,
    modbusIp: '0.0.0.0'
};

// Crear mapa de registros desde las direcciones PM2120 hasta registros Modbus secuenciales
let registerMap = new Map(); // Mapea dirección PM2120 -> índice en holdingRegisters
let reverseRegisterMap = new Map(); // Mapea índice -> dirección PM2120

function buildRegisterMap() {
    let modbusIndex = 0;

    // Handle the new "maleta virtual" registers first (addresses 1-4)
    registerMap.set(1, modbusIndex);        // Temperature
    reverseRegisterMap.set(modbusIndex, 1);
    modbusIndex += 1;

    registerMap.set(2, modbusIndex);        // Humidity
    reverseRegisterMap.set(modbusIndex, 2);
    modbusIndex += 1;

    registerMap.set(3, modbusIndex);        // Control 1
    reverseRegisterMap.set(modbusIndex, 3);
    modbusIndex += 1;

    registerMap.set(4, modbusIndex);        // Control 2
    reverseRegisterMap.set(modbusIndex, 4);
    modbusIndex += 1;

    // Handle the rest of the PM2120 registers
    pm2120Registers.forEach(reg => {
        const address = reg.address;

        // Skip addresses 1-4 since they're already handled above
        if (address >= 1 && address <= 4) {
            return; // Skip these as they are handled separately
        }

        switch(reg.data_type) {
            case 'FLOAT32':
            case '4Q_FP_PF':
            case 'DATETIME':
                registerMap.set(address, modbusIndex);
                registerMap.set(address + 1, modbusIndex + 1);
                reverseRegisterMap.set(modbusIndex, address);
                reverseRegisterMap.set(modbusIndex + 1, address + 1);
                modbusIndex += 2;
                break;
            case 'INT64':
                for (let i = 0; i < 4; i++) {
                    registerMap.set(address + i, modbusIndex + i);
                    reverseRegisterMap.set(modbusIndex + i, address + i);
                }
                modbusIndex += 4;
                break;
            case 'INT16':
            case 'INT16U':
                registerMap.set(address, modbusIndex);
                reverseRegisterMap.set(modbusIndex, address);
                modbusIndex += 1;
                break;
            default:
                registerMap.set(address, modbusIndex);
                registerMap.set(address + 1, modbusIndex + 1);
                reverseRegisterMap.set(modbusIndex, address);
                reverseRegisterMap.set(modbusIndex + 1, address + 1);
                modbusIndex += 2;
        }
    });

    registerMap.set(4000, modbusIndex);     // Bomba 1
    reverseRegisterMap.set(modbusIndex, 4000);
    modbusIndex += 1;

    registerMap.set(4001, modbusIndex);     // Bomba 2
    reverseRegisterMap.set(modbusIndex, 4001);
    modbusIndex += 1;

    registerMap.set(4002, modbusIndex);     // Nivel agua
    reverseRegisterMap.set(modbusIndex, 4002);
    modbusIndex += 1;

    return modbusIndex; // Total de registros
}

const TOTAL_REGISTERS = buildRegisterMap();
console.log(`[INIT] Total de registros Modbus: ${TOTAL_REGISTERS}`);

// Variables para almacenar los datos Modbus
let holdingRegisters = new Array(TOTAL_REGISTERS).fill(0);
let dataGenerator = null;
let modbusServer = null;

// Estados para controlar generación y envío de datos
let isDataGenerationEnabled = true;
let isDataTransmissionEnabled = true;

// Direcciones de controles industriales
const PUMP1_ADDRESS = 4000;
const PUMP2_ADDRESS = 4001;
const WATER_LEVEL_ADDRESS = 4002;

console.log(`[INIT] Registros de control:`);
console.log(`- Bomba 1: Dirección ${PUMP1_ADDRESS} -> Registro ${registerMap.get(PUMP1_ADDRESS)}`);
console.log(`- Bomba 2: Dirección ${PUMP2_ADDRESS} -> Registro ${registerMap.get(PUMP2_ADDRESS)}`);
console.log(`- Nivel agua: Dirección ${WATER_LEVEL_ADDRESS} -> Registro ${registerMap.get(WATER_LEVEL_ADDRESS)}`);


// --- CORRECCIÓN SWAPPED FLOAT: Función para convertir float32 a 2 registros (Low Word, High Word) ---
function floatToRegisters(value) {
    const buffer = Buffer.allocUnsafe(4);
    buffer.writeFloatBE(value, 0);
    // Formato "Swapped": Low word primero, High word segundo
    return [buffer.readUInt16BE(2), buffer.readUInt16BE(0)];
}

// --- CORRECCIÓN SWAPPED FLOAT: Función para reconstruir float32 desde 2 registros ---
function registersToFloat(lowWord, highWord) {
    const buffer = Buffer.allocUnsafe(4);
    buffer.writeUInt16BE(highWord, 0);
    buffer.writeUInt16BE(lowWord, 2);
    return buffer.readFloatBE(0);
}

// Función para reconstruir int64 desde 4 registros de 16 bits
function registersToInt64(reg0, reg1, reg2, reg3) {
    const buffer = Buffer.allocUnsafe(8);
    buffer.writeUInt16BE(reg0, 0);
    buffer.writeUInt16BE(reg1, 2);
    buffer.writeUInt16BE(reg2, 4);
    buffer.writeUInt16BE(reg3, 6);
    return Number(buffer.readBigInt64BE(0));
}


// Función para convertir int64 a 4 registros de 16 bits
function int64ToRegisters(value) {
    const buffer = Buffer.allocUnsafe(8);
    buffer.writeBigInt64BE(BigInt(value), 0);
    return [
        buffer.readUInt16BE(0),
        buffer.readUInt16BE(2),
        buffer.readUInt16BE(4),
        buffer.readUInt16BE(6)
    ];
}

// Función para convertir timestamp a 2 registros (DATETIME)
function timestampToRegisters() {
    const now = Math.floor(Date.now() / 1000); // Unix timestamp
    return [(now >> 16) & 0xFFFF, now & 0xFFFF];
}

// Función para generar valor según tipo de generación
function generateValue(generation) {
    switch(generation.type) {
        case 'uniform':
            const [min, max] = generation.params;
            return Math.random() * (max - min) + min;

        case 'randint':
            const [minInt, maxInt] = generation.params;
            return Math.floor(Math.random() * (maxInt - minInt + 1)) + minInt;

        case 'fixed':
            return generation.params[0];

        case 'timestamp':
            return Math.floor(Date.now() / 1000);

        default:
            return Math.random() * 100;
    }
}

// Función para generar datos aleatorios basados en PM2120 y maleta virtual
function generateRandomData() {
    if (!isDataGenerationEnabled) {
        console.log(`[DATA] Generación de datos deshabilitada - omitiendo`);
        // Si la generación está deshabilitada pero la transmisión está habilitada,
        // aún se pueden enviar datos existentes
        if (isDataTransmissionEnabled) {
            console.log(`[DATA] Enviando datos existentes a Thingsboard`);
            sendDataToThingsboard();
        }
        return;
    }

    console.log(`[DATA] Generando datos - ${new Date().toISOString()}`);

    // Handle "maleta virtual" registers (addresses 1-4)
    // Temperature (address 1) - simulated between 220-240 (representing 22.0°C to 24.0°C)
    const tempRegister = registerMap.get(1);
    if (tempRegister !== undefined) {
        const tempValue = Math.random() * (240 - 220) + 220;
        holdingRegisters[tempRegister] = Math.floor(tempValue);
    }

    // Humidity (address 2) - simulated between 300-400 (representing 30.0% to 40.0%)
    const humidityRegister = registerMap.get(2);
    if (humidityRegister !== undefined) {
        const humidityValue = Math.random() * (400 - 300) + 300;
        holdingRegisters[humidityRegister] = Math.floor(humidityValue);
    }

    // Control registers 3 and 4 should maintain their set values (0 or 1), so we don't change them here
    // They are set by user controls via API calls

    // Handle PM2120 registers
    pm2120Registers.forEach((reg, i) => {
        const address = reg.address;

        // Skip addresses 1-4 as these are handled separately above
        if (address >= 1 && address <= 4) {
            return; // Skip these
        }

        const value = generateValue(reg.generation);
        const modbusIndex = registerMap.get(address);

        switch(reg.data_type) {
            case 'FLOAT32':
            case '4Q_FP_PF':
                const floatRegs = floatToRegisters(value);
                holdingRegisters[modbusIndex] = floatRegs[0];      // Low word
                holdingRegisters[modbusIndex + 1] = floatRegs[1];  // High word
                break;

            case 'INT64':
                const int64Regs = int64ToRegisters(value);
                holdingRegisters[modbusIndex] = int64Regs[0];
                holdingRegisters[modbusIndex + 1] = int64Regs[1];
                holdingRegisters[modbusIndex + 2] = int64Regs[2];
                holdingRegisters[modbusIndex + 3] = int64Regs[3];
                break;

            case 'DATETIME':
                const timestampRegs = timestampToRegisters();
                holdingRegisters[modbusIndex] = timestampRegs[0];
                holdingRegisters[modbusIndex + 1] = timestampRegs[1];
                break;

            case 'INT16':
            case 'INT16U':
                holdingRegisters[modbusIndex] = Math.max(0, Math.min(65535, Math.floor(value)));
                break;

            default:
                const defaultRegs = floatToRegisters(value);
                holdingRegisters[modbusIndex] = defaultRegs[0];
                holdingRegisters[modbusIndex + 1] = defaultRegs[1];
        }
    });

    const pump1Register = registerMap.get(PUMP1_ADDRESS);
    const pump2Register = registerMap.get(PUMP2_ADDRESS);
    const waterLevelRegister = registerMap.get(WATER_LEVEL_ADDRESS);

    console.log(`[DATA] Datos generados para ${pm2120Registers.length} parámetros del PM2120`);
    console.log(`[DATA] Registros de control:`);
    console.log(`  - Bomba 1 (${PUMP1_ADDRESS}): ${holdingRegisters[pump1Register] ? 'ON' : 'OFF'}`);
    console.log(`  - Bomba 2 (${PUMP2_ADDRESS}): ${holdingRegisters[pump2Register] ? 'ON' : 'OFF'}`);
    console.log(`  - Nivel agua (${WATER_LEVEL_ADDRESS}): ${holdingRegisters[waterLevelRegister]}%`);

    console.log(`[DATA] Maleta Virtual:`);
    console.log(`  - Temperatura (1): ${holdingRegisters[tempRegister] / 10}°C`);
    console.log(`  - Humedad (2): ${holdingRegisters[humidityRegister] / 10}%`);
    console.log(`  - Control 1 (3): ${holdingRegisters[registerMap.get(3)] ? 'ON' : 'OFF'}`);
    console.log(`  - Control 2 (4): ${holdingRegisters[registerMap.get(4)] ? 'ON' : 'OFF'}`);

    // Enviar datos a Thingsboard después de generarlos si está habilitado
    if (isDataTransmissionEnabled) {
        sendDataToThingsboard();
    }
}

// --- Thingsboard Integration ---
function connectToThingsboard() {
    const options = {
        port: TB_PORT,
        host: TB_HOST,
        clientId: MQTT_CLIENT_ID,
        username: TB_TOKEN,
        keepalive: 60,
        reconnectPeriod: 10000, // 10 segundos
        protocolId: 'MQTT',
        protocolVersion: 4,
        clean: true,
        encoding: 'utf8'
    };

    console.log(`[MQTT] Conectando a Thingsboard en ${TB_HOST}:${TB_PORT}...`);
    mqttClient = mqtt.connect(options);

    mqttClient.on('connect', () => {
        console.log('[MQTT] ✅ Conectado exitosamente a Thingsboard');
    });

    mqttClient.on('reconnect', () => {
        console.log('[MQTT] Reconectando a Thingsboard...');
    });

    mqttClient.on('error', (err) => {
        console.error('[MQTT] ❌ Error de conexión:', err.message);
    });

    mqttClient.on('close', () => {
        console.log('[MQTT] Conexión con Thingsboard cerrada.');
    });
}

function sendDataToThingsboard() {
    if (!mqttClient || !mqttClient.connected) {
        console.log('[MQTT] Cliente no conectado. Omitiendo envío de datos.');
        return;
    }

    // Obtener los índices de los registros de la "maleta virtual"
    const tempIndex = registerMap.get(1);
    const humidityIndex = registerMap.get(2);
    const di01Index = registerMap.get(3);
    const di02Index = registerMap.get(4);

    // Crear el payload con los datos de los registros
    const payload = {
        "Temperatura": holdingRegisters[tempIndex],
        "Humedad": holdingRegisters[humidityIndex],
        "DI01": holdingRegisters[di01Index],
        "DI02": holdingRegisters[di02Index]
    };

    const payloadJson = JSON.stringify(payload);

    console.log(`[MQTT] Enviando a Thingsboard: ${payloadJson}`);
    mqttClient.publish(TB_TOPIC, payloadJson, { qos: 1 }, (err) => {
        if (err) {
            console.error('[MQTT] Error al publicar:', err);
        }
    });
}
// -----------------------------

// Inicializar servidor Modbus
function initModbusServer() {
    console.log('[MODBUS] Iniciando servidor Modbus...');

    if (modbusServer) {
        try {
            console.log('[MODBUS] Cerrando servidor anterior...');
            modbusServer.close();
            console.log('[MODBUS] Servidor anterior cerrado');
        } catch (err) {
            console.log('[MODBUS] Error cerrando servidor anterior:', err.message);
        }
    }

    const net = require('net');

    modbusServer = net.createServer(function(socket) {
        const clientInfo = `${socket.remoteAddress}:${socket.remotePort}`;
        console.log(`[MODBUS] Cliente conectado desde ${clientInfo}`);

        socket.on('data', function(data) {
            try {
                console.log(`[MODBUS] Datos recibidos de ${clientInfo}: ${data.length} bytes - ${data.toString('hex')}`);
                const response = handleModbusRequest(data);
                if (response) {
                    console.log(`[MODBUS] Enviando respuesta a ${clientInfo}: ${response.length} bytes - ${response.toString('hex')}`);
                    socket.write(response);
                } else {
                    console.log(`[MODBUS] No se generó respuesta para ${clientInfo}`);
                }
            } catch (error) {
                console.error(`[MODBUS] Error procesando solicitud de ${clientInfo}:`, error);
            }
        });

        socket.on('close', function() {
            console.log(`[MODBUS] Cliente ${clientInfo} desconectado`);
        });

        socket.on('error', function(err) {
            console.error(`[MODBUS] Error en socket de ${clientInfo}:`, err.message);
        });

        socket.setTimeout(30000); // 30 segundos timeout
        socket.on('timeout', function() {
            console.log(`[MODBUS] Timeout para cliente ${clientInfo}`);
            socket.destroy();
        });
    });

    modbusServer.listen(config.modbusPort, config.modbusIp === '0.0.0.0' ? undefined : config.modbusIp, function() {
        console.log(`[MODBUS] ✅ Servidor Modbus TCP iniciado en ${config.modbusIp}:${config.modbusPort}`);
        console.log(`[MODBUS] Device ID: ${config.deviceId}`);
        console.log(`[MODBUS] Registros disponibles: 0-${holdingRegisters.length - 1}`);
    });

    modbusServer.on('error', function(err) {
        console.error('[MODBUS] ❌ Error en servidor Modbus:', err.message);
        if (err.code === 'EADDRINUSE') {
            console.log('[MODBUS] Puerto ocupado. Intenta con otro puerto o cierra la aplicación que esté usando el puerto 502.');
        } else if (err.code === 'EACCES') {
            console.log('[MODBUS] Sin permisos para usar el puerto. Ejecuta como administrador o usa un puerto > 1024.');
        }
    });

    modbusServer.on('listening', function() {
        const address = modbusServer.address();
        console.log(`[MODBUS] Servidor escuchando en ${address.address}:${address.port}`);
    });
}

// --- CORRECCIÓN DIRECCIONAMIENTO: Función para manejar solicitudes Modbus TCP ---
function handleModbusRequest(data) {
    if (data.length < 8) {
        return null;
    }

    const transactionId = data.readUInt16BE(0);
    const protocolId = data.readUInt16BE(2);
    const unitId = data.readUInt8(6);
    const functionCode = data.readUInt8(7);

    if (protocolId !== 0) {
        return null;
    }

    if (unitId !== config.deviceId && unitId !== 0 && unitId !== 255) {
        return null;
    }

    let response = Buffer.alloc(9);
    response.writeUInt16BE(transactionId, 0);
    response.writeUInt16BE(0, 2);
    response.writeUInt8(unitId, 6);

    try {
        if (functionCode === 3) { // Read Holding Registers
            if (data.length < 12) return null;

            // La dirección en el protocolo Modbus es base-0. Los clientes como Modscan usan base-1.
            // Por lo tanto, el cliente pedirá la dirección 2999 para obtener el registro 3000.
            const startAddr = data.readUInt16BE(8);
            const quantity = data.readUInt16BE(10);
            
            console.log(`[MODBUS] Petición de lectura: ${quantity} registros desde la dirección ${startAddr} (buscando desde ${startAddr + 1})`);

            if (quantity === 0 || quantity > 125) return null;

            const responseData = [];
            for (let i = 0; i < quantity; i++) {
                const lookupAddr = startAddr + i + 1; // Sumamos 1 para alinear con nuestro mapa
                const modbusIndex = registerMap.get(lookupAddr);
                
                if (modbusIndex !== undefined) {
                    responseData.push(holdingRegisters[modbusIndex]);
                } else {
                    responseData.push(0); // Relleno si la dirección no existe
                }
            }

            const byteCount = responseData.length * 2;
            response = Buffer.alloc(9 + byteCount);
            response.writeUInt16BE(transactionId, 0);
            response.writeUInt16BE(0, 2);
            response.writeUInt16BE(3 + byteCount, 4);
            response.writeUInt8(unitId, 6);
            response.writeUInt8(3, 7);
            response.writeUInt8(byteCount, 8);

            for (let i = 0; i < responseData.length; i++) {
                response.writeUInt16BE(responseData[i], 9 + (i * 2));
            }
            return response;

        } else if (functionCode === 6) { // Write Single Register
            if (data.length < 12) return null;

            const addr = data.readUInt16BE(8);
            const value = data.readUInt16BE(10);
            const lookupAddr = addr + 1; // Sumamos 1 para alinear

            console.log(`[MODBUS] Petición de escritura: valor ${value} en la dirección ${addr} (actualizando ${lookupAddr})`);

            const modbusIndex = registerMap.get(lookupAddr);
            if (modbusIndex === undefined) return null;

            holdingRegisters[modbusIndex] = value;
            return data; // Hacemos eco de la solicitud como confirmación

        } else {
            response.writeUInt16BE(3, 4);
            response.writeUInt8(functionCode + 0x80, 7);
            response.writeUInt8(0x01, 8); // Illegal function
            return response;
        }
    } catch (error) {
        console.error('[MODBUS] ❌ Error procesando función Modbus:', error);
        response.writeUInt16BE(3, 4);
        response.writeUInt8((functionCode || 0) + 0x80, 7);
        response.writeUInt8(0x04, 8); // Server device failure
        return response;
    }
}


// Inicializar generación de datos
function startDataGeneration() {
    if (dataGenerator) {
        clearInterval(dataGenerator);
        clearTimeout(dataGenerator); // Asegurar que también se limpie cualquier timeout
        console.log('[DATA] Deteniendo generador anterior');
    }

    // Generar datos inmediatamente al iniciar
    generateRandomData();

    console.log(`[DATA] Configurando intervalo de generación: ${config.interval}ms (${config.interval/1000}s)`);

    // Usar un enfoque basado en temporizador exacto para evitar desviaciones acumuladas
    // Este enfoque calcula el momento exacto en que debe ocurrir la siguiente ejecución
    let startTime = Date.now();
    let executionCount = 1; // Ya se ejecutó una vez al inicio

    function executeAndSchedule() {
        console.log(`[DATA] Ejecutando generación programada #${executionCount} a las ${new Date().toISOString()}`);
        generateRandomData();
        executionCount++;

        // Calcular cuándo debería ocurrir la próxima ejecución para mantener intervalos precisos
        const nextExecutionTime = startTime + (executionCount * config.interval);
        const now = Date.now();
        const timeUntilNext = Math.max(0, nextExecutionTime - now);

        dataGenerator = setTimeout(executeAndSchedule, timeUntilNext);
    }

    // Calcular cuándo debería ocurrir la primera ejecución programada
    const firstExecutionTime = startTime + (executionCount * config.interval);
    const now = Date.now();
    const timeUntilFirst = Math.max(0, firstExecutionTime - now);

    dataGenerator = setTimeout(executeAndSchedule, timeUntilFirst);

    console.log(`[DATA] ✅ Generación de datos iniciada cada ${config.interval/1000} segundos`);
}

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

app.use((req, res, next) => {
    console.log(`[HTTP] ${req.method} ${req.url} - ${req.ip}`);
    next();
});

app.use((err, req, res, next) => {
    console.error('[HTTP] Error no manejado:', err);
    res.status(500).json({ error: 'Error interno del servidor', details: err.message });
});

// Rutas
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/config', (req, res) => {
    try {
        console.log('[API] GET /api/config - Enviando configuración');
        const response = {
            ...config,
            interval: config.interval / 1000, // Convertir a segundos para la interfaz
            registers: holdingRegisters
        };
        console.log('[API] Configuración enviada:', JSON.stringify(response, null, 2));
        res.json(response);
    } catch (error) {
        console.error('[API] Error en GET /api/config:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

app.post('/api/config', (req, res) => {
    try {
        console.log('[API] POST /api/config - Datos recibidos:', req.body);
        const { deviceId, interval, modbusPort, modbusIp } = req.body;

        if (deviceId !== undefined) config.deviceId = parseInt(deviceId);
        if (interval !== undefined) config.interval = parseInt(interval) * 1000;
        if (modbusPort !== undefined) config.modbusPort = parseInt(modbusPort);
        if (modbusIp !== undefined) config.modbusIp = modbusIp.trim();

        console.log('[API] Configuración actualizada:', config);

        // Reiniciar inmediatamente con la nueva configuración
        try {
            initModbusServer();
            startDataGeneration();
            console.log('[API] Servidor Modbus y generación de datos reiniciados exitosamente');
        } catch (error) {
            console.error('[API] Error reiniciando servidor Modbus:', error);
        }

        res.json({ success: true, config });
    } catch (error) {
        console.error('[API] Error en POST /api/config:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/api/registers/pumps', (req, res) => {
    try {
        console.log('[API] POST /api/registers/pumps - Datos recibidos:', req.body);
        const { pump1, pump2 } = req.body;

        const pump1Register = registerMap.get(PUMP1_ADDRESS);
        const pump2Register = registerMap.get(PUMP2_ADDRESS);

        if (pump1 !== undefined) holdingRegisters[pump1Register] = (pump1 === 'true' || pump1 === true || pump1 === 1) ? 1 : 0;
        if (pump2 !== undefined) holdingRegisters[pump2Register] = (pump2 === 'true' || pump2 === true || pump2 === 1) ? 1 : 0;

        console.log(`[API] Bombas actualizadas - Bomba 1 (${PUMP1_ADDRESS}): ${holdingRegisters[pump1Register] ? 'ON' : 'OFF'}, Bomba 2 (${PUMP2_ADDRESS}): ${holdingRegisters[pump2Register] ? 'ON' : 'OFF'}`);

        res.json({
            success: true,
            pumps: {
                pump1: holdingRegisters[pump1Register],
                pump2: holdingRegisters[pump2Register]
            }
        });
    } catch (error) {
        console.error('[API] Error en POST /api/registers/pumps:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/api/registers/water-level', (req, res) => {
    try {
        console.log('[API] POST /api/registers/water-level - Datos recibidos:', req.body);
        const { level } = req.body;

        const waterLevelRegister = registerMap.get(WATER_LEVEL_ADDRESS);

        if (level !== undefined) {
            const waterLevel = parseInt(level);
            if (!isNaN(waterLevel) && waterLevel >= 0 && waterLevel <= 100) {
                holdingRegisters[waterLevelRegister] = waterLevel;
            }
        }

        console.log(`[API] Nivel de agua actualizado (${WATER_LEVEL_ADDRESS}): ${holdingRegisters[waterLevelRegister]}%`);

        res.json({
            success: true,
            waterLevel: holdingRegisters[waterLevelRegister]
        });
    } catch (error) {
        console.error('[API] Error en POST /api/registers/water-level:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.get('/api/registers', (req, res) => {
    try {
        console.log('[API] GET /api/registers - Enviando datos de controles');

        const pump1Register = registerMap.get(PUMP1_ADDRESS);
        const pump2Register = registerMap.get(PUMP2_ADDRESS);
        const waterLevelRegister = registerMap.get(WATER_LEVEL_ADDRESS);

        const responseData = {
            controls: {
                pump1: {
                    value: holdingRegisters[pump1Register]
                },
                pump2: {
                    value: holdingRegisters[pump2Register]
                },
                waterLevel: {
                    value: holdingRegisters[waterLevelRegister]
                }
            }
        };

        res.json(responseData);

    } catch (error) {
        console.error('[API] Error en GET /api/registers:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

// API endpoints for "maleta virtual" controls
app.post('/api/registers/maleta-controls', (req, res) => {
    try {
        console.log('[API] POST /api/registers/maleta-controls - Datos recibidos:', req.body);
        const { control1, control2 } = req.body;

        const control1Register = registerMap.get(3);
        const control2Register = registerMap.get(4);

        if (control1 !== undefined) holdingRegisters[control1Register] = (control1 === 'true' || control1 === true || control1 === 1) ? 1 : 0;
        if (control2 !== undefined) holdingRegisters[control2Register] = (control2 === 'true' || control2 === true || control2 === 1) ? 1 : 0;

        console.log(`[API] Controles maleta actualizados - Control 1 (3): ${holdingRegisters[control1Register] ? 'ON' : 'OFF'}, Control 2 (4): ${holdingRegisters[control2Register] ? 'ON' : 'OFF'}`);

        res.json({
            success: true,
            controls: {
                control1: holdingRegisters[control1Register],
                control2: holdingRegisters[control2Register]
            }
        });
    } catch (error) {
        console.error('[API] Error en POST /api/registers/maleta-controls:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.get('/api/registers/maleta', (req, res) => {
    try {
        console.log('[API] GET /api/registers/maleta - Enviando datos de maleta virtual');

        const tempRegister = registerMap.get(1);
        const humidityRegister = registerMap.get(2);
        const control1Register = registerMap.get(3);
        const control2Register = registerMap.get(4);

        const responseData = {
            maleta: {
                temperature: {
                    value: holdingRegisters[tempRegister],
                    displayValue: (holdingRegisters[tempRegister] / 10).toFixed(1) + '°C'
                },
                humidity: {
                    value: holdingRegisters[humidityRegister],
                    displayValue: (holdingRegisters[humidityRegister] / 10).toFixed(1) + '%'
                },
                control1: {
                    value: holdingRegisters[control1Register]
                },
                control2: {
                    value: holdingRegisters[control2Register]
                }
            }
        };

        res.json(responseData);

    } catch (error) {
        console.error('[API] Error en GET /api/registers/maleta:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});


app.get('/api/pm2120', (req, res) => {
    try {
        console.log('[API] GET /api/pm2120 - Enviando datos del PM2120');

        const pm2120Data = pm2120Registers.map(reg => {
            const modbusIndex = registerMap.get(reg.address);
            let value, displayValue;

            switch(reg.data_type) {
                case 'FLOAT32':
                case '4Q_FP_PF':
                    const lowWord = holdingRegisters[modbusIndex] || 0;
                    const highWord = holdingRegisters[modbusIndex + 1] || 0;
                    value = registersToFloat(lowWord, highWord);
                    displayValue = value.toFixed(4);
                    break;

                case 'INT64':
                    const reg0 = holdingRegisters[modbusIndex] || 0;
                    const reg1 = holdingRegisters[modbusIndex + 1] || 0;
                    const reg2 = holdingRegisters[modbusIndex + 2] || 0;
                    const reg3 = holdingRegisters[modbusIndex + 3] || 0;
                    value = registersToInt64(reg0, reg1, reg2, reg3);
                    displayValue = value.toString();
                    break;

                case 'DATETIME':
                    const timeLow = holdingRegisters[modbusIndex] || 0;
                    const timeHigh = holdingRegisters[modbusIndex + 1] || 0;
                    const timestamp = (timeHigh << 16) | timeLow;
                    value = timestamp;
                    displayValue = new Date(timestamp * 1000).toLocaleString();
                    break;

                case 'INT16':
                case 'INT16U':
                    value = holdingRegisters[modbusIndex] || 0;
                    displayValue = value.toString();
                    break;

                default:
                    value = holdingRegisters[modbusIndex] || 0;
                    displayValue = value.toString();
            }

            return {
                description: reg.description,
                address: reg.address,
                modbusRegister: modbusIndex,
                dataType: reg.data_type,
                value: value,
                displayValue: displayValue,
                unit: reg.unit || ''
            };
        });

        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            data: pm2120Data
        });
    } catch (error) {
        console.error('[API] Error en GET /api/pm2120:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

app.get('/api/registers/table', (req, res) => {
    try {
        console.log('[API] GET /api/registers/table - Enviando tabla de registros');
        res.json(pm2120Registers);
    } catch (error) {
        console.error('[API] Error en GET /api/registers/table:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

// API endpoints para controlar generación y transmisión de datos
app.get('/api/data-control', (req, res) => {
    try {
        console.log('[API] GET /api/data-control - Enviando estados de control');
        res.json({
            dataGenerationEnabled: isDataGenerationEnabled,
            dataTransmissionEnabled: isDataTransmissionEnabled
        });
    } catch (error) {
        console.error('[API] Error en GET /api/data-control:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

app.post('/api/data-control', (req, res) => {
    try {
        console.log('[API] POST /api/data-control - Datos recibidos:', req.body);
        const { dataGenerationEnabled, dataTransmissionEnabled } = req.body;

        if (dataGenerationEnabled !== undefined) {
            isDataGenerationEnabled = Boolean(dataGenerationEnabled);
            console.log(`[API] Generación de datos ${isDataGenerationEnabled ? 'habilitada' : 'deshabilitada'}`);
        }

        if (dataTransmissionEnabled !== undefined) {
            isDataTransmissionEnabled = Boolean(dataTransmissionEnabled);
            console.log(`[API] Transmisión de datos ${isDataTransmissionEnabled ? 'habilitada' : 'deshabilitada'}`);
        }

        res.json({
            success: true,
            dataGenerationEnabled: isDataGenerationEnabled,
            dataTransmissionEnabled: isDataTransmissionEnabled
        });
    } catch (error) {
        console.error('[API] Error en POST /api/data-control:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

// Inicializar aplicación
function init() {
    try {
        console.log('[INIT] Iniciando aplicación...');

        holdingRegisters.fill(0);

        const pump1Register = registerMap.get(PUMP1_ADDRESS);
        const pump2Register = registerMap.get(PUMP2_ADDRESS);
        const waterLevelRegister = registerMap.get(WATER_LEVEL_ADDRESS);

        holdingRegisters[pump1Register] = 0;      // Bomba 1 OFF
        holdingRegisters[pump2Register] = 0;      // Bomba 2 OFF
        holdingRegisters[waterLevelRegister] = 50; // Nivel de agua 50%

        initModbusServer();
        startDataGeneration();

        // --- Conectar a Thingsboard e iniciar envío de datos ---
        connectToThingsboard();
        console.log('[INIT] ✅ Conexión con Thingsboard iniciada.');


        console.log('[INIT] ✅ Aplicación iniciada correctamente');
    } catch (error) {
        console.error('[INIT] ❌ Error iniciando aplicación:', error);
        process.exit(1);
    }
}

// Iniciar servidor web
app.listen(PORT, () => {
    console.log(`Servidor web iniciado en http://localhost:${PORT}`);
    init();
});

// Manejo de cierre limpio
process.on('SIGINT', () => {
    console.log('\nCerrando aplicación...');
    if (dataGenerator) {
        clearInterval(dataGenerator);
        clearTimeout(dataGenerator); // Asegurar que también se limpie cualquier timeout
    }
    if (modbusServer) {
        try {
            modbusServer.close();
        } catch (err) {
            console.log('Error cerrando servidor Modbus:', err.message);
        }
    }
    // --- Desconectar MQTT ---
    if (mqttClient) {
        mqttClient.end(() => {
            console.log('[MQTT] Cliente MQTT desconectado.');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});
