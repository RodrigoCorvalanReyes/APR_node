module.exports = {
  apps : [{
    name   : "virtual-rdw",
    script : "/home/pi/Documents/estacion_virtual/app.js",
    interpreter: "/home/pi/.nvm/versions/node/v22.20.0/bin/node",
    exec_mode: "fork"
  }]
}
